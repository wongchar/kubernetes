/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cm

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	libcontainercgroups "github.com/opencontainers/cgroups"
	"github.com/opencontainers/cgroups/fscommon"
	libcontainercgroupmanager "github.com/opencontainers/cgroups/manager"
	cgroupsystemd "github.com/opencontainers/cgroups/systemd"
	"k8s.io/klog/v2"
	v1helper "k8s.io/kubernetes/pkg/apis/core/v1/helper"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	"k8s.io/utils/cpuset"
)

const (
	// systemdSuffix is the cgroup name suffix for systemd
	systemdSuffix string = ".slice"
	// Cgroup2MemoryMin is memory.min for cgroup v2
	Cgroup2MemoryMin string = "memory.min"
	// Cgroup2MemoryHigh is memory.high for cgroup v2
	Cgroup2MemoryHigh      string = "memory.high"
	Cgroup2MaxCpuLimit     string = "max"
	Cgroup2MaxSwapFilename string = "memory.swap.max"
)

var RootCgroupName = CgroupName([]string{})

// NewCgroupName composes a new cgroup name.
// Use RootCgroupName as base to start at the root.
// This function does some basic check for invalid characters at the name.
func NewCgroupName(base CgroupName, components ...string) CgroupName {
	for _, component := range components {
		// Forbit using "_" in internal names. When remapping internal
		// names to systemd cgroup driver, we want to remap "-" => "_",
		// so we forbid "_" so that we can always reverse the mapping.
		if strings.Contains(component, "/") || strings.Contains(component, "_") {
			panic(fmt.Errorf("invalid character in component [%q] of CgroupName", component))
		}
	}
	return CgroupName(append(append([]string{}, base...), components...))
}

func escapeSystemdCgroupName(part string) string {
	return strings.Replace(part, "-", "_", -1)
}

func unescapeSystemdCgroupName(part string) string {
	return strings.Replace(part, "_", "-", -1)
}

// cgroupName.ToSystemd converts the internal cgroup name to a systemd name.
// For example, the name {"kubepods", "burstable", "pod1234-abcd-5678-efgh"} becomes
// "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234_abcd_5678_efgh.slice"
// This function always expands the systemd name into the cgroupfs form. If only
// the last part is needed, use path.Base(...) on it to discard the rest.
func (cgroupName CgroupName) ToSystemd() string {
	if len(cgroupName) == 0 || (len(cgroupName) == 1 && cgroupName[0] == "") {
		return "/"
	}
	newparts := []string{}
	for _, part := range cgroupName {
		part = escapeSystemdCgroupName(part)
		newparts = append(newparts, part)
	}

	result, err := cgroupsystemd.ExpandSlice(strings.Join(newparts, "-") + systemdSuffix)
	if err != nil {
		// Should never happen...
		panic(fmt.Errorf("error converting cgroup name [%v] to systemd format: %v", cgroupName, err))
	}
	return result
}

func ParseSystemdToCgroupName(name string) CgroupName {
	driverName := path.Base(name)
	driverName = strings.TrimSuffix(driverName, systemdSuffix)
	parts := strings.Split(driverName, "-")
	result := []string{}
	for _, part := range parts {
		result = append(result, unescapeSystemdCgroupName(part))
	}
	return CgroupName(result)
}

func (cgroupName CgroupName) ToCgroupfs() string {
	return "/" + path.Join(cgroupName...)
}

func ParseCgroupfsToCgroupName(name string) CgroupName {
	components := strings.Split(strings.TrimPrefix(name, "/"), "/")
	if len(components) == 1 && components[0] == "" {
		components = []string{}
	}
	return CgroupName(components)
}

func IsSystemdStyleName(name string) bool {
	return strings.HasSuffix(name, systemdSuffix)
}

// CgroupSubsystems holds information about the mounted cgroup subsystems
type CgroupSubsystems struct {
	// Cgroup subsystem mounts.
	// e.g.: "/sys/fs/cgroup/cpu" -> ["cpu", "cpuacct"]
	Mounts []libcontainercgroups.Mount

	// Cgroup subsystem to their mount location.
	// e.g.: "cpu" -> "/sys/fs/cgroup/cpu"
	MountPoints map[string]string
}

// cgroupCommon implements common tasks
// that are valid for both cgroup v1 and v2.
// This prevents duplicating the code between
// v1 and v2 specific implementations.
type cgroupCommon struct {
	// subsystems holds information about all the
	// mounted cgroup subsystems on the node
	subsystems *CgroupSubsystems

	// useSystemd tells if systemd cgroup manager should be used.
	useSystemd bool

	// The following struct fields are used when PreferAlignCgroupsByUncoreCache
	// is enabled:

	// uncoreCacheTopology stores the CPU architecture mapping of
	// uncore cache IDs to the respective CPU sets
	uncoreCacheTopology map[int]cpuset.CPUSet

	// bitmask that stores the state of uncore caches with a fully available CPUSet
	// (bit N is 1 if Cache ID N has any amount of CPUs occupied)
	occupiedUncoreMask uint64

	// tracks the CPU capacity available per uncore cache ID
	uncoreCacheCapacity map[int]int

	// tracks the quantity of CPUs designated from each
	// uncore cache by each pod
	podUncoreAllocations map[string]map[int]int

	// A mutex to ensure thread-safety during pod updates
	uncoreLock sync.Mutex
}

// Make sure that cgroupV1impl and cgroupV2impl implement the CgroupManager interface
var _ CgroupManager = &cgroupV1impl{}
var _ CgroupManager = &cgroupV2impl{}

// NewCgroupManager is a factory method that returns a CgroupManager
func NewCgroupManager(logger klog.Logger, cs *CgroupSubsystems, cgroupDriver string) CgroupManager {
	if libcontainercgroups.IsCgroup2UnifiedMode() {
		return NewCgroupV2Manager(logger, cs, cgroupDriver)
	}
	return NewCgroupV1Manager(logger, cs, cgroupDriver)
}

func newCgroupCommon(logger klog.Logger, cs *CgroupSubsystems, cgroupDriver string) cgroupCommon {
	return cgroupCommon{
		subsystems: cs,
		useSystemd: cgroupDriver == "systemd",
	}
}

// Name converts the cgroup to the driver specific value in cgroupfs form.
// This always returns a valid cgroupfs path even when systemd driver is in use!
func (m *cgroupCommon) Name(name CgroupName) string {
	if m.useSystemd {
		return name.ToSystemd()
	}
	return name.ToCgroupfs()
}

// CgroupName converts the literal cgroupfs name on the host to an internal identifier.
func (m *cgroupCommon) CgroupName(name string) CgroupName {
	if m.useSystemd {
		return ParseSystemdToCgroupName(name)
	}
	return ParseCgroupfsToCgroupName(name)
}

// buildCgroupPaths builds a path to each cgroup subsystem for the specified name.
func (m *cgroupCommon) buildCgroupPaths(name CgroupName) map[string]string {
	cgroupFsAdaptedName := m.Name(name)
	cgroupPaths := make(map[string]string, len(m.subsystems.MountPoints))
	for key, val := range m.subsystems.MountPoints {
		cgroupPaths[key] = path.Join(val, cgroupFsAdaptedName)
	}
	return cgroupPaths
}

// libctCgroupConfig converts CgroupConfig to libcontainer's Cgroup config.
func (m *cgroupCommon) libctCgroupConfig(logger klog.Logger, in *CgroupConfig, needResources bool) *libcontainercgroups.Cgroup {
	config := &libcontainercgroups.Cgroup{
		Systemd: m.useSystemd,
	}
	if needResources {
		config.Resources = m.toResources(logger, in.ResourceParameters)
	} else {
		config.Resources = &libcontainercgroups.Resources{}
	}

	if !config.Systemd {
		// For fs cgroup manager, we can either set Path or Name and Parent.
		// Setting Path is easier.
		config.Path = in.Name.ToCgroupfs()

		return config
	}

	// For systemd, we have to set Name and Parent, as they are needed to talk to systemd.
	// Setting Path is optional as it can be deduced from Name and Parent.

	// TODO(filbranden): This logic belongs in libcontainer/cgroup/systemd instead.
	// It should take a libcontainerconfigs.Cgroup.Path field (rather than Name and Parent)
	// and split it appropriately, using essentially the logic below.
	// This was done for cgroupfs in opencontainers/runc#497 but a counterpart
	// for systemd was never introduced.
	dir, base := path.Split(in.Name.ToSystemd())
	if dir == "/" {
		dir = "-.slice"
	} else {
		dir = path.Base(dir)
	}
	config.Parent = dir
	config.Name = base

	return config
}

// Destroy destroys the specified cgroup
func (m *cgroupCommon) Destroy(logger klog.Logger, cgroupConfig *CgroupConfig) error {

	start := time.Now()
	defer func() {
		metrics.CgroupManagerDuration.WithLabelValues("destroy").Observe(metrics.SinceInSeconds(start))
	}()

	libcontainerCgroupConfig := m.libctCgroupConfig(logger, cgroupConfig, false)
	manager, err := libcontainercgroupmanager.New(libcontainerCgroupConfig)
	if err != nil {
		return err
	}

	// NOTE to self!: cgroupConfig is missing info on purpose (only name is needed for destroy).

	// remove the tracked CPU restrictions so CPUs can be redistributed
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.PreferAlignCgroupByUncoreCache) {
		m.refundUncoreCapacity(cgroupConfig)
	}

	// Delete cgroups using libcontainers Managers Destroy() method
	if err = manager.Destroy(); err != nil {
		return fmt.Errorf("unable to destroy cgroup paths for cgroup %v : %v", cgroupConfig.Name, err)
	}

	return nil
}

func (m *cgroupCommon) SetCgroupConfig(logger klog.Logger, name CgroupName, resourceConfig *ResourceConfig) error {
	containerConfig := &CgroupConfig{
		Name:               name,
		ResourceParameters: resourceConfig,
	}

	return m.Update(logger, containerConfig)
}

// getCPUWeight converts from the range [2, 262144] to [1, 10000]
func getCPUWeight(cpuShares *uint64) uint64 {
	if cpuShares == nil {
		return 0
	}
	if *cpuShares >= 262144 {
		return 10000
	}
	return 1 + ((*cpuShares-2)*9999)/262142
}

var (
	availableRootControllersOnce sync.Once
	availableRootControllers     sets.Set[string]
)

func (m *cgroupCommon) toResources(logger klog.Logger, resourceConfig *ResourceConfig) *libcontainercgroups.Resources {
	resources := &libcontainercgroups.Resources{
		SkipDevices:     true,
		SkipFreezeOnSet: true,
	}
	if resourceConfig == nil {
		return resources
	}
	if resourceConfig.Memory != nil {
		resources.Memory = *resourceConfig.Memory
	}
	if resourceConfig.CPUShares != nil {
		if libcontainercgroups.IsCgroup2UnifiedMode() {
			resources.CpuWeight = getCPUWeight(resourceConfig.CPUShares)
		} else {
			resources.CpuShares = *resourceConfig.CPUShares
		}
	}
	if resourceConfig.CPUQuota != nil {
		resources.CpuQuota = *resourceConfig.CPUQuota
	}
	if resourceConfig.CPUPeriod != nil {
		resources.CpuPeriod = *resourceConfig.CPUPeriod
	}
	if resourceConfig.PidsLimit != nil {
		resources.PidsLimit = *resourceConfig.PidsLimit
	}
	if !resourceConfig.CPUSet.IsEmpty() {
		resources.CpusetCpus = resourceConfig.CPUSet.String()
	}

	m.maybeSetHugetlb(logger, resourceConfig, resources)

	// Ideally unified is used for all the resources when running on cgroup v2.
	// It doesn't make difference for the memory.max limit, but for e.g. the cpu controller
	// you can specify the correct setting without relying on the conversions performed by the OCI runtime.
	if resourceConfig.Unified != nil && libcontainercgroups.IsCgroup2UnifiedMode() {
		resources.Unified = make(map[string]string)
		for k, v := range resourceConfig.Unified {
			resources.Unified[k] = v
		}
	}
	return resources
}

func (m *cgroupCommon) maybeSetHugetlb(logger klog.Logger, resourceConfig *ResourceConfig, resources *libcontainercgroups.Resources) {
	// Check if hugetlb is supported.
	if libcontainercgroups.IsCgroup2UnifiedMode() {
		if !getSupportedUnifiedControllers().Has("hugetlb") {
			logger.V(6).Info("Optional subsystem not supported: hugetlb")
			return
		}
	} else if _, ok := m.subsystems.MountPoints["hugetlb"]; !ok {
		logger.V(6).Info("Optional subsystem not supported: hugetlb")
		return
	}

	// For each page size enumerated, set that value.
	pageSizes := sets.New[string]()
	for pageSize, limit := range resourceConfig.HugePageLimit {
		sizeString, err := v1helper.HugePageUnitSizeFromByteSize(pageSize)
		if err != nil {
			logger.Info("Invalid pageSize", "err", err)
			continue
		}
		resources.HugetlbLimit = append(resources.HugetlbLimit, &libcontainercgroups.HugepageLimit{
			Pagesize: sizeString,
			Limit:    uint64(limit),
		})
		pageSizes.Insert(sizeString)
	}
	// for each page size omitted, limit to 0
	for _, pageSize := range libcontainercgroups.HugePageSizes() {
		if pageSizes.Has(pageSize) {
			continue
		}
		resources.HugetlbLimit = append(resources.HugetlbLimit, &libcontainercgroups.HugepageLimit{
			Pagesize: pageSize,
			Limit:    uint64(0),
		})
	}
}

// Update updates the cgroup with the specified Cgroup Configuration
func (m *cgroupCommon) Update(logger klog.Logger, cgroupConfig *CgroupConfig) error {
	start := time.Now()
	defer func() {
		metrics.CgroupManagerDuration.WithLabelValues("update").Observe(metrics.SinceInSeconds(start))
	}()

	libcontainerCgroupConfig := m.libctCgroupConfig(logger, cgroupConfig, true)
	manager, err := libcontainercgroupmanager.New(libcontainerCgroupConfig)
	if err != nil {
		return fmt.Errorf("failed to create cgroup manager: %v", err)
	}
	return manager.Set(libcontainerCgroupConfig.Resources)
}

// Create creates the specified cgroup
func (m *cgroupCommon) Create(logger klog.Logger, cgroupConfig *CgroupConfig) error {
	start := time.Now()
	defer func() {
		metrics.CgroupManagerDuration.WithLabelValues("create").Observe(metrics.SinceInSeconds(start))
	}()

	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.PreferAlignCgroupByUncoreCache) &&
		len(m.uncoreCacheTopology) > 0 && cgroupConfig != nil && cgroupConfig.ResourceParameters != nil {

		logger.Info("DEBUG: Cgroup Update Triggered", "name", fmt.Sprintf("%v", cgroupConfig.Name))

		nameStr := fmt.Sprintf("%v", cgroupConfig.Name)

		if cgroupConfig.ResourceParameters.CPUSet.IsEmpty() {
			rp := cgroupConfig.ResourceParameters
			neededCores := 0

			// TODO: check number of uncore caches, skip if number of uncore is <=2
			// TODO: currently not compatible with static CPU manager
			// TODO: implement detection of static CPU manager allocation here
			// TODO: current assumption is for integer CPUs, need to handle fractional CPUs too

			// Calculate CPU quantity: Limit (Quota) takes priority over Request (Shares)
			if rp.CPUQuota != nil && rp.CPUPeriod != nil && *rp.CPUPeriod > 0 {
				// Quantity = Quota / Period (e.g., 200000 / 100000 = 2 cores)
				neededCores = int(*rp.CPUQuota / int64(*rp.CPUPeriod))
			} else if rp.CPUShares != nil {
				// Fallback to Request: Shares / 1024 (e.g., 2048 / 1024 = 2 cores)
				neededCores = int(*rp.CPUShares / 1024)
			}

			// TODO: this logic breaks coreDNS initialization (0.1 cpus), need to revisit
			// If calculation yields 0 (e.g. very small pod with fractional CPU requirement),
			// treat as 1 core to ensure it gets at least one isolated cache.
			//if neededCores <= 0 && (rp.CPUQuota != nil || rp.CPUShares != nil) {
			//	neededCores = 1
			//}

			// PreferAlignCgroupsByUncoreCache applies to Guaranteed and Burstable QoS
			// ignore Best Effort QoS
			if neededCores > 0 {
				// Obtain the optimal CPUSets by groups of uncore cache
				// Restrict the cgroup CPUs of the pod to the obtained CPUSet
				alignedSet := m.allocateUncoreCaches(cgroupConfig, neededCores)

				if !alignedSet.IsEmpty() {
					// Set the CPUSet in the ResourceParameters config before libcontainer is initialized
					rp.CPUSet = alignedSet
					logger.Info("PreferAlignCgroupByUncoreCache: Aligned pod to uncore cache domain",
						"pod", nameStr,
						"cpus", rp.CPUSet.String(),
						"needed", neededCores)
				}
			}
		}
	}

	libcontainerCgroupConfig := m.libctCgroupConfig(logger, cgroupConfig, true)
	manager, err := libcontainercgroupmanager.New(libcontainerCgroupConfig)
	if err != nil {
		return err
	}

	// Apply(-1) is a hack to create the cgroup directories for each resource
	// subsystem. The function [cgroups.Manager.apply()] applies cgroup
	// configuration to the process with the specified pid.
	// It creates cgroup files for each subsystems and writes the pid
	// in the tasks file. We use the function to create all the required
	// cgroup files but not attach any "real" pid to the cgroup.
	if err := manager.Apply(-1); err != nil {
		return err
	}

	// it may confuse why we call set after we do apply, but the issue is that runc
	// follows a similar pattern.  it's needed to ensure cpu quota is set properly.
	if err := manager.Set(libcontainerCgroupConfig.Resources); err != nil {
		utilruntime.HandleError(fmt.Errorf("cgroup manager.Set failed: %w", err))
	}

	return nil
}

// Scans through all subsystems to find pids associated with specified cgroup.
func (m *cgroupCommon) Pids(logger klog.Logger, name CgroupName) []int {
	// we need the driver specific name
	cgroupFsName := m.Name(name)

	// Get a list of processes that we need to kill
	pidsToKill := sets.New[int]()
	var pids []int
	for _, val := range m.subsystems.MountPoints {
		dir := path.Join(val, cgroupFsName)
		_, err := os.Stat(dir)
		if os.IsNotExist(err) {
			// The subsystem pod cgroup is already deleted
			// do nothing, continue
			continue
		}
		// Get a list of pids that are still charged to the pod's cgroup
		pids, err = getCgroupProcs(dir)
		if err != nil {
			continue
		}
		pidsToKill.Insert(pids...)

		// WalkFunc which is called for each file and directory in the pod cgroup dir
		visitor := func(path string, info os.FileInfo, err error) error {
			if err != nil {
				logger.V(4).Info("Cgroup manager encountered error scanning cgroup path", "path", path, "err", err)
				return filepath.SkipDir
			}
			if !info.IsDir() {
				return nil
			}
			pids, err = getCgroupProcs(path)
			if err != nil {
				logger.V(4).Info("Cgroup manager encountered error getting procs for cgroup path", "path", path, "err", err)
				return filepath.SkipDir
			}
			pidsToKill.Insert(pids...)
			return nil
		}
		// Walk through the pod cgroup directory to check if
		// container cgroups haven't been GCed yet. Get attached processes to
		// all such unwanted containers under the pod cgroup
		if err = filepath.Walk(dir, visitor); err != nil {
			logger.V(4).Info("Cgroup manager encountered error scanning pids for directory", "path", dir, "err", err)
		}
	}
	return sets.List(pidsToKill)
}

// ReduceCPULimits reduces the cgroup's cpu shares to the lowest possible value
func (m *cgroupCommon) ReduceCPULimits(logger klog.Logger, cgroupName CgroupName) error {
	// Set lowest possible CpuShares value for the cgroup
	minimumCPUShares := uint64(MinShares)
	resources := &ResourceConfig{
		CPUShares: &minimumCPUShares,
	}
	containerConfig := &CgroupConfig{
		Name:               cgroupName,
		ResourceParameters: resources,
	}
	return m.Update(logger, containerConfig)
}

func readCgroupMemoryConfig(cgroupPath string, memLimitFile string) (*ResourceConfig, error) {
	memLimit, err := fscommon.GetCgroupParamUint(cgroupPath, memLimitFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s for cgroup %v: %v", memLimitFile, cgroupPath, err)
	}
	mLim := int64(memLimit)
	//TODO(vinaykul,InPlacePodVerticalScaling): Add memory request support
	return &ResourceConfig{Memory: &mLim}, nil

}

// When PreferAlignCgroupsByUncoreCache is enabled, build store the
// uncore cache topology in the cgroupCommon struct
func (m *cgroupCommon) SetUncoreCacheTopology(topo map[int]cpuset.CPUSet) {
	m.uncoreLock.Lock()
	defer m.uncoreLock.Unlock()

	// Set the topology
	m.uncoreCacheTopology = topo

	// Initialize the CPU capacity map based on the uncore cache topology
	m.uncoreCacheCapacity = make(map[int]int)
	for id, cacheCPUSet := range topo {
		m.uncoreCacheCapacity[id] = cacheCPUSet.Size()
	}

	// Initialize pod tracker for uncore cache CPU allocations
	m.podUncoreAllocations = make(map[string]map[int]int)

	// Reset the mask (every uncore cache starts as 0/Pristine)
	m.occupiedUncoreMask = 0
}

func (m *cgroupCommon) allocateUncoreCaches(config *CgroupConfig, needed int) cpuset.CPUSet {
	m.uncoreLock.Lock()
	defer m.uncoreLock.Unlock()

	result := cpuset.New()
	remaining := needed
	// We use the unique cgroup Path as the key for the podUncoreAllocations map
	identifier := strings.Join(config.Name, "/")
	// Track exactly how many CPUs are assigned from each cache ID for this specific pod
	podUncoreRecord := make(map[int]int)

	// Ensure stable iteration order for the occupiedUncoreMask bitmask/topology
	// (iteration over maps is random in order)
	ids := make([]int, 0, len(m.uncoreCacheTopology))
	for id := range m.uncoreCacheTopology {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	// Attempt to allocate full uncore cache worth of CPUs (aka "Pristine" uncore cache)
	for _, id := range ids {
		isPristine := (m.occupiedUncoreMask & (1 << uint(id))) == 0
		if isPristine {
			cacheCPUs := m.uncoreCacheTopology[id]
			capacity := m.uncoreCacheCapacity[id]

			// Determine quantity of CPUs to take from this pristine cache
			take := capacity
			if remaining < capacity {
				take = remaining
			}

			// Allocate the full cache affinity to the CPUSet
			result = result.Union(cacheCPUs)

			// Record the actual core count debt
			podUncoreRecord[id] = take

			// Update Global States
			// Turn on bit to indicate cache is not pristine
			m.occupiedUncoreMask |= (1 << uint(id))
			// Track quantity of CPUs given from this uncore cache
			m.uncoreCacheCapacity[id] -= take
			// Subtract the given CPUs from the needed quantity
			remaining -= take
		}
		if remaining <= 0 {
			break
		}
	}

	// If we still need more cores, we now look at caches that are already
	// partially occupied (isPristine == false).
	// TODO: Sort by most available uncore cache capacity to be efficient
	// and reduce uncore cache spread
	if remaining > 0 {
		for _, id := range ids {
			isPristine := (m.occupiedUncoreMask & (1 << uint(id))) == 0
			// Only look at non-pristine uncore caches (already occupied)
			if !isPristine {
				available := m.uncoreCacheCapacity[id]
				if available > 0 {
					cacheCPUs := m.uncoreCacheTopology[id]

					take := available
					if remaining < available {
						take = remaining
					}

					result = result.Union(cacheCPUs)

					// Add to existing record for this ID
					podUncoreRecord[id] += take

					m.uncoreCacheCapacity[id] -= take
					remaining -= take
				}
			}
			if remaining <= 0 {
				break
			}
		}
	}

	// Store the finalized record for Destroy()
	m.podUncoreAllocations[identifier] = podUncoreRecord

	return result
}

func (m *cgroupCommon) refundUncoreCapacity(config *CgroupConfig) {
	// Generate the same unique identifier used during uncore cache allocation
	identifier := strings.Join(config.Name, "/")

	m.uncoreLock.Lock()
	defer m.uncoreLock.Unlock()

	// Retrieve the pod's specific allocation record
	podUncoreRecord, exists := m.podUncoreAllocations[identifier]
	if !exists {
		return
	}

	// Perform the refund of uncore cache CPU capacity
	for id, amount := range podUncoreRecord {
		m.uncoreCacheCapacity[id] += amount

		maxSize := m.uncoreCacheTopology[id].Size()
		if m.uncoreCacheCapacity[id] >= maxSize {
			m.uncoreCacheCapacity[id] = maxSize
			// Turn bit OFF (back to pristine)
			m.occupiedUncoreMask &= ^(1 << uint(id))
		}
	}

	// Cleanup the tracking map
	delete(m.podUncoreAllocations, identifier)
}
