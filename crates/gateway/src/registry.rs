//! Provider adapter registry (DR-09 GW-01: Gateway is the sole
//! provider-aware subsystem). Adapters are registered by kind; routes are
//! resolved by flat ModelRef → ProviderRouteBinding. The registry also
//! carries the trust allowlist so the Trust gate has a single source.

use crate::ModelRef;
use orbit_adapter::types::{AdapterKind, ProviderRouteBinding};
use orbit_adapter::ProviderAdapter;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// The gateway's registry: model allowlist, model→route table, and the
/// adapter instances by kind. This is the ONLY provider-aware state.
#[derive(Default)]
pub struct ProviderRegistry {
    allowlisted_models: HashSet<ModelRef>,
    model_to_route: HashMap<String, ProviderRouteBinding>,
    adapters: HashMap<AdapterKind, Arc<dyn ProviderAdapter>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_model(&mut self, model: ModelRef, route: ProviderRouteBinding) {
        self.allowlisted_models.insert(model.clone());
        self.model_to_route.insert(model.0.clone(), route);
    }

    pub fn register_adapter(&mut self, kind: AdapterKind, adapter: Arc<dyn ProviderAdapter>) {
        self.adapters.insert(kind, adapter);
    }

    pub fn is_model_allowed(&self, model: &str) -> bool {
        self.allowlisted_models.iter().any(|m| m.0 == model)
    }

    pub fn route_for_model(&self, model: &str) -> Option<ProviderRouteBinding> {
        self.model_to_route.get(model).cloned()
    }

    pub fn resolve_adapter(&self, kind: AdapterKind) -> Option<Arc<dyn ProviderAdapter>> {
        self.adapters.get(&kind).cloned()
    }

    pub fn adapter_kinds(&self) -> Vec<AdapterKind> {
        self.adapters.keys().copied().collect()
    }
}
