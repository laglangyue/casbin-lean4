import Casbin.Runtime

namespace Casbin

private def unwrap (value : Except String α) : IO α :=
  match value with | .ok result => pure result | .error error => throw (IO.userError error)

/-- Configuration participates in transaction versioning and invalidates decisions. -/
def RuntimeEnforcer.configure (runtime : RuntimeEnforcer) (fn : Enforcer → Except String Enforcer) : IO Unit :=
  runtime.state.atomically do
    let state ← MonadState.get
    let enforcer ← unwrap (fn state.enforcer)
    for rule in enforcer.rules do unwrap (rule.validate enforcer.model)
    unwrap (validateConstraints enforcer.model enforcer.rules)
    set { state with enforcer := enforcer, version := state.version + 1, configurationVersion := state.configurationVersion + 1, cache := [] }

def Enforcer.setEffector (e : Enforcer) (effector : Effector) : Enforcer := { e with effector := some effector }
def Enforcer.enableAutoBuildRoleLinks (e : Enforcer) (enabled : Bool) : Enforcer :=
  { e with roleSnapshot := if enabled then none else some (e.roleSnapshot.getD e.rules) }
def Enforcer.buildRoleLinks (e : Enforcer) : Enforcer :=
  { e with roleSnapshot := e.roleSnapshot.map (fun _ => e.rules) }
def Enforcer.setRoleManager (e : Enforcer) (manager : RoleManager) (ptype : String := "g") : Except String Enforcer := do
  let _ ← findDefinition e.model.roles ptype
  return { e with roleManagers := (ptype, manager) :: e.roleManagers.filter (·.1 != ptype) }

def RuntimeEnforcer.getPolicy (runtime : RuntimeEnforcer) (ptype : String := "p") : IO (List (List String)) :=
  return (← runtime.snapshot).getPolicy ptype
def RuntimeEnforcer.clearPolicy (runtime : RuntimeEnforcer) : IO Bool :=
  runtime.mutate (fun e => .ok (e.clearPolicy, !e.rules.isEmpty)) false
def RuntimeEnforcer.addPoliciesEx (runtime : RuntimeEnforcer) (rows : List (List String)) (ptype : String := "p") : IO Bool :=
  runtime.mutate (fun e => e.addPoliciesEx rows ptype)
def RuntimeEnforcer.updatePolicies (runtime : RuntimeEnforcer) (oldRows newRows : List (List String))
    (ptype : String := "p") : IO Bool := runtime.mutate (fun e => e.updatePolicies oldRows newRows ptype)
def RuntimeEnforcer.removeFilteredPolicy (runtime : RuntimeEnforcer) (index : Nat) (values : List String)
    (ptype : String := "p") : IO Bool := runtime.mutate (fun e => e.removeFilteredPolicy index values ptype)
def RuntimeEnforcer.updateFilteredPolicies (runtime : RuntimeEnforcer) (rows : List (List String))
    (index : Nat) (values : List String) (ptype : String := "p") : IO Bool :=
  runtime.mutate (fun e => e.updateFilteredPolicies rows index values ptype)
def RuntimeEnforcer.addGroupingPolicies (runtime : RuntimeEnforcer) (rows : List (List String))
    (ptype : String := "g") (skipExisting : Bool := false) : IO Bool :=
  runtime.mutate (fun e => e.addGroupingPolicies rows ptype skipExisting)
def RuntimeEnforcer.removeGroupingPolicies (runtime : RuntimeEnforcer) (rows : List (List String))
    (ptype : String := "g") : IO Bool := runtime.removePolicies rows ptype
def RuntimeEnforcer.updateGroupingPolicy (runtime : RuntimeEnforcer) (oldRow newRow : List String)
    (ptype : String := "g") : IO Bool := runtime.updatePolicy oldRow newRow ptype
def RuntimeEnforcer.updateGroupingPolicies (runtime : RuntimeEnforcer) (oldRows newRows : List (List String))
    (ptype : String := "g") : IO Bool := runtime.updatePolicies oldRows newRows ptype
def RuntimeEnforcer.removeFilteredGroupingPolicy (runtime : RuntimeEnforcer) (index : Nat) (values : List String)
    (ptype : String := "g") : IO Bool := runtime.removeFilteredPolicy index values ptype

def RuntimeEnforcer.enableAutoNotifyWatcher (runtime : RuntimeEnforcer) (enabled : Bool) : IO Unit :=
  runtime.state.atomically do modify fun s => { s with notifyWatcher := enabled }
def RuntimeEnforcer.enableAutoNotifyDispatcher (runtime : RuntimeEnforcer) (enabled : Bool) : IO Unit :=
  runtime.state.atomically do modify fun s => { s with notifyDispatcher := enabled }
def RuntimeEnforcer.setLogger (runtime : RuntimeEnforcer) (logger : List Value → Decision → IO Unit) : IO Unit :=
  runtime.state.atomically do modify fun s => { s with logger := some logger }
def RuntimeEnforcer.enforceLogged (runtime : RuntimeEnforcer) (request : List Value) (ctx : Context := {}) : IO Decision := do
  runtime.enforceValuesEx request ctx
def RuntimeEnforcer.batchEnforce (runtime : RuntimeEnforcer) (requests : List (List Value))
    (ctx : Context := {}) : IO (List Bool) := requests.mapM fun r => return (← runtime.enforceValuesEx r ctx).allow
def RuntimeEnforcer.enforceWithMatcher (runtime : RuntimeEnforcer) (matcher : String)
    (request : List Value) (ctx : Context := {}) : IO Decision := do
  let e ← runtime.snapshot
  unwrap ({ e with now := ← currentTime }.enforceWithMatcher matcher request ctx)

def Transaction.snapshot (tx : Transaction) : IO Enforcer := tx.state.atomically do
  let s ← MonadState.get
  if !s.active then throw (IO.userError "transaction is closed")
  return s.working
def Transaction.isActive (tx : Transaction) : IO Bool := tx.state.atomically do return (← MonadState.get).active
def Transaction.operationCount (tx : Transaction) : IO Nat := tx.state.atomically do return (← MonadState.get).operations
def Transaction.hasOperations (tx : Transaction) : IO Bool := return (← tx.operationCount) > 0
def Transaction.id (tx : Transaction) : IO String := tx.state.atomically do
  return "tx-" ++ toString (← MonadState.get).identifier
def RuntimeEnforcer.getTransaction (runtime : RuntimeEnforcer) (id : String) : IO (Option Transaction) :=
  runtime.state.atomically do
    let s ← MonadState.get
    return (s.transactions.find? (fun (key, _) => id == "tx-" ++ toString key)).map fun (_, state) => ⟨runtime, state⟩
def RuntimeEnforcer.isTransactionActive (runtime : RuntimeEnforcer) (id : String) : IO Bool := do
  if let some tx ← runtime.getTransaction id then tx.isActive else pure false
def Transaction.addPolicy (tx : Transaction) (row : List String) (ptype : String := "p") : IO Bool :=
  tx.mutate (fun e => e.addPolicy row ptype)
def Transaction.removePolicy (tx : Transaction) (row : List String) (ptype : String := "p") : IO Bool :=
  tx.mutate (fun e => e.removePolicy row ptype)
def Transaction.addPolicies (tx : Transaction) (rows : List (List String)) (ptype : String := "p") : IO Bool :=
  tx.mutate (fun e => e.addPolicies rows ptype)
def Transaction.removePolicies (tx : Transaction) (rows : List (List String)) (ptype : String := "p") : IO Bool :=
  tx.mutate (fun e => e.removePolicies rows ptype)
def Transaction.updatePolicy (tx : Transaction) (oldRow newRow : List String) (ptype : String := "p") : IO Bool :=
  tx.mutate (fun e => e.updatePolicy oldRow newRow ptype)
def Transaction.updatePolicies (tx : Transaction) (oldRows newRows : List (List String))
    (ptype : String := "p") : IO Bool := tx.mutate (fun e => e.updatePolicies oldRows newRows ptype)
def Transaction.removeFilteredPolicy (tx : Transaction) (index : Nat) (values : List String)
    (ptype : String := "p") : IO Bool := tx.mutate (fun e => e.removeFilteredPolicy index values ptype)

structure PoolState where
  entries : List (String × RuntimeEnforcer) := []
  generation : Nat := 0

/-- Factories run outside the mutex; invalidation during loading forces a fresh load. -/
structure EnforcerPool where
  factory : String → PolicyFilter → IO RuntimeEnforcer
  capacity : Nat
  state : Std.Mutex PoolState

def EnforcerPool.new (factory : String → PolicyFilter → IO RuntimeEnforcer) (capacity : Nat := 100) : IO EnforcerPool :=
  return ⟨factory, capacity, ← Std.Mutex.new {}⟩

partial def EnforcerPool.get (pool : EnforcerPool) (key : String) (filter : PolicyFilter := {}) : IO RuntimeEnforcer := do
  let (cached, generation) ← pool.state.atomically do
    let state ← MonadState.get
    let cached := state.entries.find? (·.1 == key)
    if let some entry := cached then
      set { state with entries := entry :: state.entries.filter (·.1 != key) }
    return (cached.map Prod.snd, state.generation)
  if let some e := cached then return e
  let created ← pool.factory key filter
  let result ← pool.state.atomically do
    let state ← MonadState.get
    if generation != state.generation then return none
    let selected := ((state.entries.find? (·.1 == key)).map Prod.snd).getD created
    let entries := (key, selected) :: state.entries.filter (·.1 != key)
    set { state with entries := if pool.capacity == 0 then entries else entries.take pool.capacity }
    return some selected
  if let some e := result then return e
  pool.get key filter

def EnforcerPool.invalidate (pool : EnforcerPool) (key : String) : IO Unit := pool.state.atomically do
  modify fun s => { s with entries := s.entries.filter (·.1 != key), generation := s.generation + 1 }
def EnforcerPool.invalidateAll (pool : EnforcerPool) : IO Unit := pool.state.atomically do
  modify fun s => { s with entries := [], generation := s.generation + 1 }
def EnforcerPool.size (pool : EnforcerPool) : IO Nat := pool.state.atomically do return (← MonadState.get).entries.length
def EnforcerPool.filtered (model : Enforcer) (adapterFactory : IO Adapter) (capacity : Nat := 100) : IO EnforcerPool :=
  EnforcerPool.new (fun _ filter => do
    let e ← RuntimeEnforcer.new model
    e.setAdapter (← adapterFactory)
    e.loadPolicy (some filter)
    return e) capacity

/-- Background reloads are cancellable between IO calls; errors are available to the caller. -/
structure AutoLoader where
  runtime : RuntimeEnforcer
  generation : Nat
  task : Task (Except IO.Error Unit)

def RuntimeEnforcer.startAutoLoadPolicy (runtime : RuntimeEnforcer) (intervalMs : Nat) : IO AutoLoader := do
  if intervalMs == 0 then throw (IO.userError "autoload interval must be positive")
  let generation ← runtime.state.atomically do
    let s ← MonadState.get
    if s.autoLoadRunning then throw (IO.userError "policy autoload already running")
    let generation := s.autoLoadGeneration + 1
    set { s with autoLoadRunning := true, autoLoadGeneration := generation, autoLoadError := none }
    return generation
  let task ← IO.asTask (prio := .dedicated) do
    let mut last ← IO.monoMsNow
    repeat
      IO.sleep (UInt32.ofNat (min intervalMs 25))
      let running ← runtime.state.atomically do
        let s ← MonadState.get
        return s.autoLoadRunning && s.autoLoadGeneration == generation
      if !running then break
      let now ← IO.monoMsNow
      if now - last ≥ intervalMs then
        try
          runtime.loadPolicy
          runtime.state.atomically do modify fun s => { s with autoLoadError := none }
        catch error =>
          runtime.state.atomically do modify fun s => { s with autoLoadError := some (toString error) }
        last := now
  return ⟨runtime, generation, task⟩

def AutoLoader.stop (loader : AutoLoader) : IO Unit := do
  loader.runtime.state.atomically do
    modify fun s => if s.autoLoadGeneration == loader.generation then { s with autoLoadRunning := false } else s
  IO.ofExcept loader.task.get

def RuntimeEnforcer.isAutoLoadingRunning (runtime : RuntimeEnforcer) : IO Bool :=
  runtime.state.atomically do return (← MonadState.get).autoLoadRunning

def RuntimeEnforcer.applyRemoteVersioned (runtime : RuntimeEnforcer) (source : String)
    (version : Nat) (rules : List Rule) : IO Bool := runtime.state.atomically do
  let s ← MonadState.get
  let previous := ((s.remoteVersions.find? (·.1 == source)).map Prod.snd).getD 0
  if version ≤ previous then return false
  for rule in rules do unwrap (rule.validate s.enforcer.model)
  unwrap (validateConstraints s.enforcer.model rules)
  set { s with
    enforcer := { s.enforcer with rules := rules }
    version := s.version + 1
    cache := []
    remoteVersions := (source, version) :: s.remoteVersions.filter (·.1 != source)
  }
  return true

end Casbin
