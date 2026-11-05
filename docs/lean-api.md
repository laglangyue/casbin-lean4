# Lean API and Go correspondence

Import `Casbin`. The library exposes two layers: immutable `Enforcer` operations in `Except String`, and shared `RuntimeEnforcer` operations in `IO`. Named policy parameters are explicit strings; request values are `List Value`, or `List String` through the compatibility entry points. Lean mutation results contain the updated enforcer and a change flag.

| Go API family | Lean entry points |
| --- | --- |
| NewEnforcer / model constructors | `Enforcer.fromText`, `fromFiles`, `fromModel`, `Model.parse`, `fromFile`, `toText` |
| Enforce / EnforceEx / BatchEnforce | `enforce`, `enforceEx`, `enforceValues`, `enforceValuesEx`, `enforceValuesIO`, `batchEnforce` |
| EnforceWithMatcher / named contexts | `enforceWithMatcher`, `batchEnforceWithMatcher`, `Context` selecting r/p/e/m definitions |
| Management APIs | `getPolicy`, `getFilteredPolicy`, `hasPolicy`, batch add/remove/update, filtered update and grouping variants |
| Named management APIs | Optional `ptype` on operations and `getNamedPolicy`, `addNamedPolicies`, `updateNamedPolicy` and related aliases |
| Field indexes and enumeration | `getFieldIndex`, `setFieldIndex`, `getAllSubjects`, `getAllObjects`, `getAllActions`, `getAllRoles` |
| Direct RBAC | `getRolesForUser`, `getUsersForRole`, `hasRoleForUser`, role and permission add/delete helpers |
| Implicit RBAC | Implicit roles/users/permissions/resources, users for permissions/resources and allowed object conditions |
| RBAC with domains | Optional domain arguments, `getAllDomains`, `getDomainsForUser`, domain users/roles and deletion helpers |
| Custom functions and conditions | `addFunction`, `addValueFunction`, `addMatchingFunction`, `addLinkConditionFunction`, `setLinkConditionParams`, `addTimeCondition` |
| Effectors and role managers | `setEffector`, `setRoleManager`, `Effector`, `RoleManager`; callbacks receive current validated policy records |
| Config | `Config.parse`, `fromFile`, `get`, `set`, `addConfig`, typed bool/int/int64/float64/string getters |
| File / string / filtered persistence | `Adapter.file`, `string`, `memory`, `sqlite`, `PolicyFilter`, runtime load/save |
| Synced / cached / distributed / transactional enforcers | Type aliases of `RuntimeEnforcer`, configurable using cache, adapters, notifications and transactions |
| Enforcer pool | `EnforcerPool.new`, `filtered`, `get`, `invalidate`, `invalidateAll`, `size` |
| Background reload | `startAutoLoadPolicy`, `AutoLoader.stop`, `isAutoLoadingRunning`; last failure in runtime state |
| Context adapters | `OperationContext`, `ContextAdapter`, `ContextEnforcer`: load/save/mutate/enforce and cooperative checks |
| Transactions | `beginTransaction`, `withTransaction`, `Transaction` mutations/commit/rollback/snapshot/ID/count, runtime lookup |
| Watcher / dispatcher | `setWatcher`, `addWatcher`, `setDispatcher`, automatic notification toggles, `PolicyEvent.added/removed` |
| Distributed self-operations | `runtime.mutate operation persist publish`; use `publish := false` for self operations, remote snapshots suppress notifications |
| Cycle detector | `detectCycles`, also used by CLI validation |
| Frontend / AI explanation | `casbinJsGetPermissionForUser`, `explain`, `AIConfig`, injectable `AITransport`, `curlAITransport` |

The correspondence is at the level of behavior and features. Go interfaces, reflection, goroutine scheduling, caches used only as optimizations, and internal helper structures are expressed using Lean types and runtime services rather than copied literally.

## Values and contexts

`Value` represents strings, booleans, Float numbers, property objects, arrays and null. Attribute paths such as `r.sub.Name` traverse objects. Use `Value.object [("Name", .text "alice"), ("Age", .number 21)]` for ABAC. String requests can opt into JSON decoding with `enableAcceptJsonRequest true`.

`Context` selects `requestType`, `policyType`, `effectType` and `matcherType`. It is distinct from `OperationContext`, which carries cancellation and a monotonic deadline. For deterministic condition tests, set the immutable enforcer's `now` field. IO execution refreshes UTC time before every decision.

`Function` is a string-argument boolean callback. `ValueFunction` accepts and returns typed values. An `Effector` receives effect kind plus policy effects, matcher scores and explanation records. Custom effect strings require supplying an effector at construction. Role managers receive current grouping records on each call.

## Persistence and shared state

Runtime state is protected by `Std.Mutex`. Cache keys include values and named context; mutations, loads and configuration clear cached decisions. Conditions disable decision caching. Capacity zero means unbounded; expiry zero means no time-based expiry.

`RuntimeEnforcer.new e (some adapter)` loads that adapter. File and string adapters use explicit save, matching Go's file-adapter behavior. Memory and SQLite support incremental automatic persistence. SQLite keeps a database write transaction open while Lean checks the merged rules and constraints, preserving unrelated updates made by another enforcer. Storage errors occur before the in-memory state is published.

Filters select rules by policy fields, with empty strings as wildcards. Saving or automatically persisting an incomplete filtered snapshot is rejected. Incremental filtered loads keep the filtered flag until a complete replacement load.

Notifications and log callbacks run outside the runtime mutex. A notification failure reports that the policy change already committed. Register transports with callbacks; no remote service is started automatically. `applyRemoteVersioned source version rules` rejects stale snapshots from the same source. Cross-source merge and durable message delivery belong to the transport.

Configuration uses `runtime.configure` and changes a separate configuration version. Transactions reject configuration changes during their lifetime.

## Transactions

A transaction reads its own working snapshot; other callers cannot see uncommitted rules. Commit validates constraints and persistence before publishing. Concurrent modifications to unrelated rules are merged. Removal or replacement of a rule touched by another transaction produces a conflict. IDs are unique within the runtime and closed transactions leave its active registry.

`withTransaction` commits on success and rolls back on failure. Watcher failures after a successful commit do not undo that commit. Direct `Transaction.commit` failures leave it active for inspection or rollback. Read snapshots remain immutable.

## Cancellation, pools and background loading

`ContextAdapter` receives an `OperationContext` and must check it during long operations. The framework checks before reads, before publication and before mutations. It does not interrupt arbitrary noncooperative IO. Cancellation after a successful storage commit cannot be treated as a rollback.

An `EnforcerPool` key uniquely identifies a filter. Factories run on a miss outside its mutex, and invalidation during a load forces a fresh result. Concurrent misses may run a factory more than once; only one result is kept. Capacity zero is unbounded. Invalidate after external policy updates or from a watcher callback.

`AutoLoader.stop` waits for its task to exit. Polling waits are short; an in-progress adapter call completes before shutdown. Reload errors remain inspectable as `autoLoadError` and are retried on later intervals.

## Validation limits

The checked-in reference fixtures cover decisions and explanations. Operator fixtures additionally cover malformed input handling, path extraction, glob behavior, RE2 features, numeric precedence and typed logical errors. Persistence and cancellation tests perform actual IO. The AI transport is tested with a loopback HTTP server, and replication with local callbacks and out-of-order snapshots.

The port does not prove authorization properties, adapter crash recovery, or arbitrary network behavior. Go's reflected methods must be provided as Lean functions. Date literals without an offset use UTC, and out-of-range float-to-integer conversions can differ across Go architectures. Native RE2 fixes its Unicode tables to the pinned dependency version. These boundaries should be included in application-level validation.
