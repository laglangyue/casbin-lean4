import Casbin.Operations

namespace Casbin

/-- Cancellation is cooperative. Context-aware adapters must check this token during IO. -/
structure OperationContext where
  cancelled : IO.Ref Bool
  deadline : Option Nat := none

def OperationContext.new (timeoutMs : Option Nat := none) : IO OperationContext := do
  let now ← IO.monoMsNow
  return ⟨← IO.mkRef false, timeoutMs.map (now + ·)⟩
def OperationContext.cancel (ctx : OperationContext) : IO Unit := ctx.cancelled.set true
def OperationContext.check (ctx : OperationContext) : IO Unit := do
  if ← ctx.cancelled.get then throw (IO.userError "operation cancelled")
  if let some deadline := ctx.deadline then
    if (← IO.monoMsNow) ≥ deadline then throw (IO.userError "operation deadline exceeded")

structure ContextAdapter where
  load : OperationContext → Model → IO (List Rule)
  save : OperationContext → Model → List Rule → IO Unit

structure ContextEnforcer where
  runtime : RuntimeEnforcer
  adapter : ContextAdapter

def ContextEnforcer.new (e : Enforcer) (adapter : ContextAdapter) : IO ContextEnforcer :=
  return ⟨← RuntimeEnforcer.new e, adapter⟩
def ContextEnforcer.loadPolicy (e : ContextEnforcer) (ctx : OperationContext)
    (filter : Option PolicyFilter := none) : IO Unit := do
  ctx.check
  let base ← e.runtime.snapshot
  let rules ← e.adapter.load ctx base.model
  ctx.check
  let rules := match filter with | none => rules | some f => rules.filter f.accepts
  -- Applying and marking the filter happen in one critical section.
  e.runtime.state.atomically do
    let state ← get
    for rule in rules do
      match rule.validate state.enforcer.model with
      | .error error => throw (IO.userError error)
      | .ok _ => pure ()
    match validateConstraints state.enforcer.model rules with
    | .error error => throw (IO.userError error)
    | .ok _ => pure ()
    ctx.check
    set { state with
      enforcer := { state.enforcer with rules := rules }
      filtered := filter.isSome
      cache := []
      version := state.version + 1
    }
def ContextEnforcer.savePolicy (e : ContextEnforcer) (ctx : OperationContext) : IO Unit :=
  e.runtime.state.atomically do
    ctx.check
    let state ← get
    if state.filtered then throw (IO.userError "cannot save a filtered policy snapshot")
    e.adapter.save ctx state.enforcer.model state.enforcer.rules
def ContextEnforcer.mutate (e : ContextEnforcer) (ctx : OperationContext)
    (operation : Enforcer → Except String (Enforcer × Bool)) : IO Bool := do
  ctx.check
  -- Persistence is performed by the context adapter before committing the snapshot.
  let event ← e.runtime.state.atomically do
    let state ← get
    ctx.check
    let (updated, changed) ← match operation state.enforcer with
      | .ok value => pure value | .error error => throw (IO.userError error)
    if !changed then return none
    for rule in updated.rules do
      match rule.validate updated.model with
      | .error error => throw (IO.userError error) | .ok _ => pure ()
    match validateConstraints updated.model updated.rules with
    | .error error => throw (IO.userError error) | .ok _ => pure ()
    if state.autoSave then
      if state.filtered then throw (IO.userError "cannot persist a filtered policy snapshot")
      e.adapter.save ctx updated.model updated.rules
    let version := state.version + 1
    set { state with enforcer := updated, version := version, cache := [] }
    return some (PolicyEvent.mk version state.enforcer.rules updated.rules,
      (if state.notifyWatcher then state.watchers else []),
      (if state.notifyDispatcher then state.dispatcher.toList else []))
  if let some (event, watchers, dispatchers) := event then
    notifyPolicyEvent event watchers dispatchers.head?
    return true
  return false
def ContextEnforcer.enforce (e : ContextEnforcer) (ctx : OperationContext) (request : List Value) : IO Decision := do
  ctx.check
  let decision ← e.runtime.enforceValuesEx request
  ctx.check
  return decision

private partial def findCycle (edges : List (String × String)) (node : String) (path : List String)
    (fuel : Nat) : Option (List String) := do
  if let some idx := path.findIdx? (· == node) then return path.drop idx ++ [node]
  if fuel == 0 then none
  else
    ((edges.filter (·.1 == node)).filterMap fun (_, parent) =>
      findCycle edges parent (path ++ [node]) (fuel - 1)).head?

def Enforcer.detectCycles (e : Enforcer) (ptype : String := "g") : Except String Unit := do
  let defn ← findDefinition e.model.roles ptype
  let domains := if defn.fields.length == 3 then
    ((e.getGroupingPolicy ptype).filterMap (·[2]?)).eraseDups.map some else [none]
  for domain in domains do
    let rules := (e.getGroupingPolicy ptype).filter fun row => domain.isNone || row[2]? == domain
    let edges := rules.map fun row => (row[0]?.getD "", row[1]?.getD "")
    for (node, _) in edges do
      if let some cycle := findCycle edges node [] (edges.length + 1) then
        throw ("role cycle: " ++ String.intercalate " -> " cycle)

/-- Casbin.js export includes all policies and model definitions, as in the Go frontend API. -/
def Enforcer.casbinJsGetPermissionForUser (e : Enforcer) (_user : String) : String :=
  let policy := e.rules.filter (fun r => e.model.policies.any (·.name == r.ptype))
  let roles := e.rules.filter (fun r => e.model.roles.any (·.name == r.ptype))
  (Lean.Json.mkObj [("m", .str e.model.toText),
    ("p", Lean.toJson (policy.map fun r => r.ptype :: r.values)),
    ("g", Lean.toJson (roles.map fun r => r.ptype :: r.values))]).compress ++ "\n"

structure AIConfig where
  endpoint : String
  model : String
  apiKey : String := ""
  timeoutMs : Nat := 30000

abbrev AITransport := AIConfig → Lean.Json → IO Lean.Json

private def curlQuote (s : String) : String :=
  let escaped := s.replace "\\" "\\\\" |>.replace "\"" "\\\"" |>.replace "\n" "\\n" |>.replace "\r" "\\r"
  "\"" ++ escaped ++ "\""

/-- Curl receives credentials and request data on stdin. No endpoint is contacted by default. -/
def curlAITransport : AITransport := fun config body => do
  let timeout := toString (max 1 ((config.timeoutMs + 999) / 1000))
  let settings := "url = " ++ curlQuote config.endpoint ++ "\nrequest = \"POST\"\n" ++
    "header = \"Content-Type: application/json\"\nheader = " ++
    curlQuote ("Authorization: Bearer " ++ config.apiKey) ++ "\ndata = " ++ curlQuote body.compress ++ "\n"
  let process ← IO.Process.spawn { cmd := "curl", args := #["--silent", "--show-error", "--fail-with-body",
    "--max-time", timeout, "--config", "-"], stdin := .piped, stdout := .piped, stderr := .piped }
  process.stdin.putStr settings
  let (_, process) ← process.takeStdin
  let outputTask ← IO.asTask process.stdout.readToEnd
  let errors ← process.stderr.readToEnd
  let code ← process.wait
  let output ← IO.ofExcept outputTask.get
  if code != 0 then throw (IO.userError ("AI request failed: " ++ errors))
  match Lean.Json.parse output with
  | .ok value => return value | .error error => throw (IO.userError error)

def Enforcer.explain (e : Enforcer) (request : List Value) (config : AIConfig)
    (transport : AITransport := curlAITransport) : IO String := do
  if config.endpoint.isEmpty then throw (IO.userError "AI endpoint is not configured")
  let decision ← e.enforceValuesIO request
  let context := Lean.Json.mkObj [("request", Lean.toJson request), ("allow", Lean.toJson decision.allow),
    ("matchedPolicy", Lean.toJson decision.explain), ("model", .str e.model.source),
    ("policies", Lean.toJson (e.rules.map fun r => r.ptype :: r.values))]
  let message := fun role content => Lean.Json.mkObj [("role", .str role), ("content", .str content)]
  let body := Lean.Json.mkObj [("model", .str config.model), ("messages", .arr #[
    message "system" "Explain why this authorization request was allowed or denied using the supplied model and policies.",
    message "user" context.compress])]
  let response ← transport config body
  if let .ok error := response.getObjVal? "error" then throw (IO.userError s!"AI error: {error.compress}")
  let result := do
    let choices ← response.getObjVal? "choices" >>= Lean.Json.getArr?
    let some first := choices[0]? | throw "no response from AI"
    let message ← first.getObjVal? "message"
    message.getObjValAs? String "content"
  match result with | .ok content => return content | .error error => throw (IO.userError error)

end Casbin
