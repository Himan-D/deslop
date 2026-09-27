use crate::{GraphAnalyzer, SymbolGraph};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub name: String,
    pub tier: String,
    pub cpu_cores: usize,
    pub ram_mb: usize,
    pub bandwidth_mbps: usize,
    pub base_memory_overhead_mb: usize,
}

impl DeviceProfile {
    pub fn standard_profiles() -> Vec<Self> {
        vec![
            Self {
                name: "High-Perf Cloud Server (AWS c7g.8xlarge)".to_string(),
                tier: "Cloud Enterprise".to_string(),
                cpu_cores: 32,
                ram_mb: 65536, // 64 GB
                bandwidth_mbps: 12500,
                base_memory_overhead_mb: 512,
            },
            Self {
                name: "Standard Cloud VM (AWS t4g.xlarge / Linode 16GB)".to_string(),
                tier: "Production VM".to_string(),
                cpu_cores: 4,
                ram_mb: 16384, // 16 GB
                bandwidth_mbps: 1000,
                base_memory_overhead_mb: 256,
            },
            Self {
                name: "Edge Gateway / Mini-PC (Raspberry Pi 5 / N100)".to_string(),
                tier: "Edge Hardware".to_string(),
                cpu_cores: 4,
                ram_mb: 4096, // 4 GB
                bandwidth_mbps: 300,
                base_memory_overhead_mb: 128,
            },
            Self {
                name: "Mobile / Embedded Client (ARM Cortex-A55 / Phone)".to_string(),
                tier: "Mobile / IoT".to_string(),
                cpu_cores: 2,
                ram_mb: 2048, // 2 GB
                bandwidth_mbps: 50,
                base_memory_overhead_mb: 96,
            },
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakdownRisk {
    pub trigger_pattern: String,
    pub failure_mode: String,
    pub estimated_breaking_threshold: String,
    pub affected_symbol: String,
    pub file_location: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityEstimate {
    pub device: DeviceProfile,
    pub max_concurrent_users: usize,
    pub max_requests_per_sec: usize,
    pub bottleneck_resource: String,
    pub memory_per_user_kb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityReport {
    pub scalability_grade: String,
    pub estimated_complexity_class: String,
    pub estimates: Vec<CapacityEstimate>,
    pub breaking_risks: Vec<BreakdownRisk>,
}

pub struct CapacityAnalyzer;

impl GraphAnalyzer for CapacityAnalyzer {
    type Report = CapacityReport;

    fn analyze(graph: &SymbolGraph) -> CapacityReport {
        let mut quadratic_loops = Vec::new();
        let mut unbounded_allocs = Vec::new();
        let mut deep_recursion_risks = Vec::new();
        let mut blocking_in_handlers = Vec::new();

        let mut max_complexity = 1;
        let mut total_complexity = 0;
        let mut function_count = 0;

        for idx in graph.graph.node_indices() {
            let sym = &graph.graph[idx];
            if sym.cyclomatic_complexity > max_complexity {
                max_complexity = sym.cyclomatic_complexity;
            }
            total_complexity += sym.cyclomatic_complexity;
            function_count += 1;

            let sig_lower = sym.signature.to_lowercase();
            let name_lower = sym.name.to_lowercase();

            // Detect potential quadratic bottlenecks (nested loops / high complexity)
            if sym.cyclomatic_complexity >= 8 && sym.loc > 30 {
                quadratic_loops.push(BreakdownRisk {
                    trigger_pattern: "High Cyclomatic Density with Branching Loops".to_string(),
                    failure_mode: "CPU Saturation & P99 Latency Spike (>5,000ms)".to_string(),
                    estimated_breaking_threshold: "~1,200 concurrent requests".to_string(),
                    affected_symbol: sym.name.clone(),
                    file_location: format!("{}:{}", sym.file_path.display(), sym.span.start_line),
                    recommendation: "Decompose nested branching and cache repetitive computation."
                        .to_string(),
                });
            }

            // Detect memory accumulation / unbounded collection risks
            if (sig_lower.contains("vec<")
                || sig_lower.contains("hashmap<")
                || sig_lower.contains("array")
                || name_lower.contains("cache")
                || name_lower.contains("buffer"))
                && sym.loc > 20
            {
                unbounded_allocs.push(BreakdownRisk {
                    trigger_pattern: "Unbounded In-Memory Collection / Buffer".to_string(),
                    failure_mode: "Out-Of-Memory (OOM) Kernel Kill".to_string(),
                    estimated_breaking_threshold: "~18,000 active sessions or large payloads"
                        .to_string(),
                    affected_symbol: sym.name.clone(),
                    file_location: format!("{}:{}", sym.file_path.display(), sym.span.start_line),
                    recommendation:
                        "Apply an explicit LRU capacity bound and stream large payloads."
                            .to_string(),
                });
            }

            // Detect blocking or synchronous file/network operations in handlers
            if (name_lower.contains("handle")
                || name_lower.contains("service")
                || name_lower.contains("route"))
                && (sig_lower.contains("sleep")
                    || sig_lower.contains("read_to_string")
                    || sig_lower.contains("blocking"))
            {
                blocking_in_handlers.push(BreakdownRisk {
                    trigger_pattern: "Synchronous Blocking Call in Request Path".to_string(),
                    failure_mode: "Thread Pool Starvation (Entire Server Hangs)".to_string(),
                    estimated_breaking_threshold: "~200 concurrent requests exhausting thread pool".to_string(),
                    affected_symbol: sym.name.clone(),
                    file_location: format!("{}:{}", sym.file_path.display(), sym.span.start_line),
                    recommendation: "Offload blocking operations to async workers or tokio::task::spawn_blocking.".to_string(),
                });
            }
        }

        // Check for recursive risk
        let cycles = graph.find_circular_dependencies();
        for cycle in cycles {
            deep_recursion_risks.push(BreakdownRisk {
                trigger_pattern: "Mutual Circular Dependency in Execution Path".to_string(),
                failure_mode: "Call Stack Overflow (SIGSEGV / Program Crash)".to_string(),
                estimated_breaking_threshold: "Depth > 1,024 recursive stack frames".to_string(),
                affected_symbol: cycle.join(" ⇄ "),
                file_location: "Cross-file mutual dependency".to_string(),
                recommendation:
                    "Apply Dependency Inversion or Leaf Module Extraction to break the loop."
                        .to_string(),
            });
        }

        // Combine all breaking risks
        let mut breaking_risks = Vec::new();
        breaking_risks.extend(deep_recursion_risks);
        breaking_risks.extend(blocking_in_handlers);
        breaking_risks.extend(quadratic_loops);
        breaking_risks.extend(unbounded_allocs);

        // Grade the codebase scalability
        let scalability_grade = if breaking_risks.is_empty() && max_complexity < 6 {
            "A (Linearly Scalable - Cloud Ready)".to_string()
        } else if breaking_risks.len() <= 2 && max_complexity < 10 {
            "B (Moderate Scalability - Minor Bottlenecks)".to_string()
        } else if breaking_risks.len() <= 5 {
            "C (Contention Heavy - Will Choke Under Spike)".to_string()
        } else {
            "D (Fragile - Immediate Saturation Risks)".to_string()
        };

        let avg_complexity = if function_count > 0 {
            total_complexity as f64 / function_count as f64
        } else {
            1.0
        };

        let complexity_class = if avg_complexity < 2.0 {
            "O(1) to O(log N) - Highly Parallel".to_string()
        } else if avg_complexity < 4.0 {
            "O(N) - Linear Scaling".to_string()
        } else {
            "O(N log N) to O(N^2) - Sub-Linear Scalability".to_string()
        };

        // Base memory per user session (roughly based on codebase complexity)
        let memory_per_user_kb = (128.0 + (avg_complexity * 32.0)).clamp(64.0, 1024.0);

        // Project capacity for each standard hardware profile
        let devices = DeviceProfile::standard_profiles();
        let mut estimates = Vec::new();

        for dev in devices {
            let available_ram_kb = (dev.ram_mb.saturating_sub(dev.base_memory_overhead_mb)) * 1024;
            let mem_user_limit = (available_ram_kb as f64 / memory_per_user_kb) as usize;

            // CPU throughput: cores * base ops per core adjusted by complexity
            let base_ops_per_core = 4000.0 / avg_complexity.max(1.0);
            let max_rps = (dev.cpu_cores as f64 * base_ops_per_core) as usize;

            // Little's Law: Concurrent users = RPS * avg user wait/think time (typically ~2-5s per request in interactive use)
            let cpu_user_limit = max_rps * 3;

            // Bottleneck determination
            let (max_users, bottleneck) = if mem_user_limit < cpu_user_limit {
                (mem_user_limit, "Memory (RAM Saturation)".to_string())
            } else {
                (cpu_user_limit, "CPU Compute & Core Throughput".to_string())
            };

            // If critical breaking risks exist, discount capacity by risk factor
            let penalty_factor = if !breaking_risks.is_empty() {
                (1.0 - (breaking_risks.len() as f64 * 0.15)).max(0.15)
            } else {
                1.0
            };

            let safe_users = ((max_users as f64) * penalty_factor) as usize;
            let safe_rps = ((max_rps as f64) * penalty_factor) as usize;

            estimates.push(CapacityEstimate {
                device: dev,
                max_concurrent_users: safe_users,
                max_requests_per_sec: safe_rps,
                bottleneck_resource: bottleneck,
                memory_per_user_kb,
            });
        }

        CapacityReport {
            scalability_grade,
            estimated_complexity_class: complexity_class,
            estimates,
            breaking_risks,
        }
    }
}
