import Casbin.Adapter

namespace Casbin

structure PolicyEvent where
  version : Nat
  before : List Rule
  after : List Rule
  deriving Repr

abbrev Watcher := PolicyEvent → IO Unit
abbrev Dispatcher := PolicyEvent → IO Unit

structure CacheEntry where
  key : String
  decision : Decision
  expiry : Nat

structure TransactionState where
  working : Enforcer
  original : List Rule
  baseVersion : Nat
  active : Bool := true
  operations : Nat := 0
  identifier : Nat := 0
  baseConfiguration : Nat := 0
  changes : List (List Rule × List Rule) := []


structure RuntimeState where
  enforcer : Enforcer
  adapter : Option Adapter := none
  filtered : Bool := false
  version : Nat := 0
  configurationVersion : Nat := 0
  nextTransactionId : Nat := 0
  transactions : List (Nat × Std.Mutex TransactionState) := []
  remoteVersions : List (String × Nat) := []
  autoSave : Bool := true
  watchers : List Watcher := []
  dispatcher : Option Dispatcher := none
  cacheEnabled : Bool := false
  cacheTTL : Nat := 0
  cacheCapacity : Nat := 1000
  cache : List CacheEntry := []
  notifyWatcher : Bool := true
  notifyDispatcher : Bool := true
  autoLoadRunning : Bool := false
  autoLoadGeneration : Nat := 0
  autoLoadError : Option String := none
  logger : Option (List Value → Decision → IO Unit) := none

/-- Shared execution, persistence, and cache state guarded by a real mutex. -/
structure RuntimeEnforcer where
  state : Std.Mutex RuntimeState

private def unwrap (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

private def validateRules (model : Model) (rules : List Rule) : IO Unit := do
  for rule in rules do unwrap (rule.validate model)
  unwrap (validateConstraints model rules)

def RuntimeEnforcer.new (enforcer : Enforcer) (adapter : Option Adapter := none) : IO RuntimeEnforcer := do
  let mut e := enforcer
  if let some adapter := adapter then
    let loaded ← adapter.load e.model
    let rules := loaded.eraseDups
    validateRules e.model rules
    e := { e with rules := rules }
  return ⟨← Std.Mutex.new { enforcer := e, adapter := adapter }⟩

def RuntimeEnforcer.snapshot (runtime : RuntimeEnforcer) : IO Enforcer :=
  runtime.state.atomically do return (← get).enforcer

private def cacheKey (request : List Value) (ctx : Context) : String :=
  (Lean.Json.arr #[Lean.toJson ctx.requestType, Lean.toJson ctx.policyType,
    Lean.toJson ctx.effectType, Lean.toJson ctx.matcherType, Lean.toJson request]).compress

private def RuntimeEnforcer.computeDecision (runtime : RuntimeEnforcer) (request : List Value)
    (ctx : Context := {}) : IO Decision := runtime.state.atomically do
  let state ← get
  let key := cacheKey request ctx
  let now ← IO.monoMsNow
  let useCache := state.cacheEnabled && state.enforcer.conditions.isEmpty
  if useCache then
    if let some entry := state.cache.find? (fun entry => entry.key == key &&
        (entry.expiry == 0 || now < entry.expiry)) then
      set { state with cache := entry :: state.cache.filter (·.key != key) }
      return entry.decision
  let result ← state.enforcer.enforceValuesIO request ctx
  if useCache then
    let entry := CacheEntry.mk key result (if state.cacheTTL == 0 then 0 else now + state.cacheTTL)
    let capacity := if state.cacheCapacity == 0 then state.cache.length + 1 else state.cacheCapacity
    set { state with cache := (entry :: state.cache.filter (·.key != key)).take capacity }
  return result

def RuntimeEnforcer.enforceValuesEx (runtime : RuntimeEnforcer) (request : List Value) (ctx : Context := {}) : IO Decision := do
  let decision ← runtime.computeDecision request ctx
  let logger ← runtime.state.atomically do return (← get).logger
  if let some logger := logger then logger request decision
  return decision

def RuntimeEnforcer.enforceEx (runtime : RuntimeEnforcer) (request : List String) (ctx : Context := {}) : IO Decision :=
  runtime.enforceValuesEx (request.map Value.text) ctx

def RuntimeEnforcer.enforce (runtime : RuntimeEnforcer) (request : List String) (ctx : Context := {}) : IO Bool :=
  return (← runtime.enforceEx request ctx).allow

def notifyPolicyEvent (event : PolicyEvent) (watchers : List Watcher) (dispatcher : Option Dispatcher) : IO Unit := do
  let mut errors := []
  for watcher in watchers ++ dispatcher.toList do
    try watcher event catch error => errors := errors ++ [toString error]
  if !errors.isEmpty then throw (IO.userError ("policy change committed; notification failed: " ++ String.intercalate "; " errors))

def RuntimeEnforcer.mutate (runtime : RuntimeEnforcer) (operation : Enforcer → Except String (Enforcer × Bool))
    (persist : Bool := true) (publish : Bool := true) : IO Bool := do
  let result ← runtime.state.atomically do
    let state ← get
    let (updated, changed) ← unwrap (operation state.enforcer)
    if !changed then return none
    validateRules updated.model updated.rules
    if persist && state.autoSave then
      if let some adapter := state.adapter then
        if adapter.supportsIncremental then
          if state.filtered then throw (IO.userError "cannot persist a filtered policy snapshot")
          match adapter.apply with
          | some apply => apply updated.model state.enforcer.rules updated.rules
          | none => adapter.save updated.model updated.rules
    let version := state.version + 1
    set { state with enforcer := updated, version := version, cache := [] }
    return some (PolicyEvent.mk version state.enforcer.rules updated.rules, (if state.notifyWatcher then state.watchers else []), (if state.notifyDispatcher then state.dispatcher else none))
  if let some (event, watchers, dispatcher) := result then
    if publish then notifyPolicyEvent event watchers dispatcher
    return true
  return false

def RuntimeEnforcer.addPolicy (runtime : RuntimeEnforcer) (values : List String) (ptype : String := "p") : IO Bool :=
  runtime.mutate (fun e => e.addPolicy values ptype)
def RuntimeEnforcer.removePolicy (runtime : RuntimeEnforcer) (values : List String) (ptype : String := "p") : IO Bool :=
  runtime.mutate (fun e => e.removePolicy values ptype)
def RuntimeEnforcer.addPolicies (runtime : RuntimeEnforcer) (values : List (List String)) (ptype : String := "p") : IO Bool :=
  runtime.mutate (fun e => e.addPolicies values ptype)
def RuntimeEnforcer.removePolicies (runtime : RuntimeEnforcer) (values : List (List String)) (ptype : String := "p") : IO Bool :=
  runtime.mutate (fun e => e.removePolicies values ptype)
def RuntimeEnforcer.updatePolicy (runtime : RuntimeEnforcer) (oldValues newValues : List String) (ptype : String := "p") : IO Bool :=
  runtime.mutate (fun e => e.updatePolicy oldValues newValues ptype)
def RuntimeEnforcer.addGroupingPolicy (runtime : RuntimeEnforcer) (values : List String) (ptype : String := "g") : IO Bool :=
  runtime.mutate (fun e => e.addGroupingPolicy values ptype)
def RuntimeEnforcer.removeGroupingPolicy (runtime : RuntimeEnforcer) (values : List String) (ptype : String := "g") : IO Bool :=
  runtime.mutate (fun e => e.removeGroupingPolicy values ptype)

def RuntimeEnforcer.savePolicy (runtime : RuntimeEnforcer) : IO Unit := runtime.state.atomically do
  let state ← get
  if state.filtered then throw (IO.userError "cannot save a filtered policy snapshot")
  let some adapter := state.adapter | throw (IO.userError "no policy adapter configured")
  adapter.save state.enforcer.model state.enforcer.rules

def RuntimeEnforcer.loadPolicy (runtime : RuntimeEnforcer) (filter : Option PolicyFilter := none)
    (incremental : Bool := false) : IO Unit := runtime.state.atomically do
  let state ← get
  let some adapter := state.adapter | throw (IO.userError "no policy adapter configured")
  let loaded ← adapter.load state.enforcer.model
  let rules := loaded.eraseDups
  let rules := match filter with | none => rules | some f => rules.filter f.accepts
  let combined := if incremental then (state.enforcer.rules ++ rules).eraseDups else rules
  validateRules state.enforcer.model combined
  set { state with enforcer := { state.enforcer with rules := combined }, filtered := filter.isSome ||
    (incremental && state.filtered), version := state.version + 1, cache := [] }

def RuntimeEnforcer.setWatcher (runtime : RuntimeEnforcer) (watcher : Watcher) : IO Unit :=
  runtime.state.atomically do modify fun state => { state with watchers := [watcher] }
def RuntimeEnforcer.addWatcher (runtime : RuntimeEnforcer) (watcher : Watcher) : IO Unit :=
  runtime.state.atomically do modify fun state => { state with watchers := state.watchers ++ [watcher] }
def RuntimeEnforcer.setDispatcher (runtime : RuntimeEnforcer) (dispatcher : Dispatcher) : IO Unit :=
  runtime.state.atomically do modify fun state => { state with dispatcher := some dispatcher }
def RuntimeEnforcer.enableAutoSave (runtime : RuntimeEnforcer) (enabled : Bool) : IO Unit :=
  runtime.state.atomically do modify fun state => { state with autoSave := enabled }
def RuntimeEnforcer.setAdapter (runtime : RuntimeEnforcer) (adapter : Adapter) : IO Unit :=
  runtime.state.atomically do modify fun state => { state with adapter := some adapter }
def RuntimeEnforcer.isFiltered (runtime : RuntimeEnforcer) : IO Bool :=
  runtime.state.atomically do return (← get).filtered
def RuntimeEnforcer.enableCache (runtime : RuntimeEnforcer) (enabled : Bool) (ttlMilliseconds : Nat := 0)
    (capacity : Nat := 1000) : IO Unit := runtime.state.atomically do
  modify fun state => { state with
    cacheEnabled := enabled
    cacheTTL := ttlMilliseconds
    cacheCapacity := capacity
    cache := []
  }
def RuntimeEnforcer.invalidateCache (runtime : RuntimeEnforcer) : IO Unit :=
  runtime.state.atomically do modify fun state => { state with cache := [] }
def RuntimeEnforcer.applyRemote (runtime : RuntimeEnforcer) (rules : List Rule) : IO Unit := do
  let _ ← runtime.mutate (fun e => do
    for rule in rules do rule.validate e.model
    validateConstraints e.model rules
    return ({ e with rules := rules }, e.rules != rules)) false false


structure Transaction where
  owner : RuntimeEnforcer
  state : Std.Mutex TransactionState

def RuntimeEnforcer.beginTransaction (runtime : RuntimeEnforcer) : IO Transaction := runtime.state.atomically do
  let state ← get
  let identifier := state.nextTransactionId + 1
  let txState ← Std.Mutex.new {
    working := state.enforcer
    original := state.enforcer.rules
    baseVersion := state.version
    identifier := identifier
    baseConfiguration := state.configurationVersion
  }
  set { state with nextTransactionId := identifier, transactions := (identifier, txState) :: state.transactions }
  return ⟨runtime, txState⟩

def Transaction.mutate (transaction : Transaction) (operation : Enforcer → Except String (Enforcer × Bool)) : IO Bool :=
  transaction.state.atomically do
    let state ← get
    if !state.active then throw (IO.userError "transaction is closed")
    let (updated, changed) ← unwrap (operation state.working)
    let removed := state.working.rules.filter (!updated.rules.contains ·)
    let added := updated.rules.filter (!state.working.rules.contains ·)
    set { state with
      working := updated
      operations := state.operations + (if changed then 1 else 0)
      changes := if changed then state.changes ++ [(removed, added)] else state.changes
    }
    return changed

def Transaction.enforceEx (transaction : Transaction) (request : List String) : IO Decision :=
  transaction.state.atomically do
    let state ← get
    if !state.active then throw (IO.userError "transaction is closed")
    state.working.enforceValuesIO (request.map Value.text)

def Transaction.commit (transaction : Transaction) : IO Unit := do
  let result ← transaction.state.atomically do
    let tx ← get
    if !tx.active then throw (IO.userError "transaction is closed")
    let result ← transaction.owner.state.atomically do
      let state ← get
      if state.configurationVersion != tx.baseConfiguration then throw (IO.userError "transaction conflict: configuration changed")
      if tx.original == tx.working.rules then
        set { state with transactions := state.transactions.filter (·.1 != tx.identifier) }
        return none
      let mut rules := tx.working.rules
      if state.version != tx.baseVersion then
        rules := state.enforcer.rules
        for (removed, added) in tx.changes do
          if removed.any (!rules.contains ·) then throw (IO.userError "transaction conflict: policy was removed or updated")
          if !removed.isEmpty && added.any (fun r => rules.contains r && !removed.contains r) then
            throw (IO.userError "transaction conflict: replacement policy already exists")
          if removed.length == added.length then
            let pairs := removed.zip added
            rules := rules.map fun r => ((pairs.find? (·.1 == r)).map Prod.snd).getD r
          else rules := (rules.filter (!removed.contains ·) ++ added).eraseDups
      let updated := { state.enforcer with rules := rules }
      validateRules updated.model rules
      if state.autoSave then
        if state.filtered then throw (IO.userError "cannot commit a filtered policy snapshot")
        if let some adapter := state.adapter then
          match adapter.apply with
          | some apply => apply updated.model state.enforcer.rules rules
          | none => adapter.save updated.model rules
      let version := state.version + 1
      set { state with enforcer := updated, version := version, cache := [], transactions := state.transactions.filter (·.1 != tx.identifier) }
      return some (PolicyEvent.mk version state.enforcer.rules rules, (if state.notifyWatcher then state.watchers else []), (if state.notifyDispatcher then state.dispatcher else none))
    set { tx with active := false }
    return result
  if let some (event, watchers, dispatcher) := result then notifyPolicyEvent event watchers dispatcher

def Transaction.rollback (transaction : Transaction) : IO Unit := transaction.state.atomically do
  let state ← get
  if !state.active then throw (IO.userError "transaction is closed")
  set { state with active := false }
  transaction.owner.state.atomically do
    modify fun owner => { owner with transactions := owner.transactions.filter (·.1 != state.identifier) }

def RuntimeEnforcer.withTransaction (runtime : RuntimeEnforcer) (fn : Transaction → IO α) : IO α := do
  let tx ← runtime.beginTransaction
  try
    let value ← fn tx
    tx.commit
    return value
  catch error =>
    try tx.rollback catch _ => pure ()
    throw error

abbrev SyncedEnforcer := RuntimeEnforcer
abbrev CachedEnforcer := RuntimeEnforcer
abbrev DistributedEnforcer := RuntimeEnforcer
abbrev TransactionalEnforcer := RuntimeEnforcer

end Casbin
