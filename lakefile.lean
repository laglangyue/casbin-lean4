import Lake
open System Lake DSL

package casbin where
  version := v!"0.2.0"
  -- Select the system GCC runtime explicitly instead of Lean's C++ linker shim.
  moreLinkArgs := if System.Platform.isOSX then #["-lc++"] else #["-l:libstdc++.so.6", "-lpthread"]

extern_lib casbin_re2 pkg := do
  let src ← inputTextFile (pkg.dir / "native" / "regex.cpp")
  let buildSource ← inputTextFile (pkg.dir / "scripts" / "build-re2.py")
  let inputs := Job.collectArray #[src, buildSource]
  inputs.mapM fun _ => do
    let output := pkg.sharedLibDir / nameToStaticLib "casbin_re2"
    let art ← buildArtifactUnlessUpToDate output (ext := "a") (restore := true) do
      proc { cmd := "python3", args := #[(pkg.dir / "scripts" / "build-re2.py").toString,
        (← getLeanIncludeDir).toString, output.toString] }
    return art.path

@[default_target]
lean_lib Casbin where
  precompileModules := true

lean_lib CasbinTests where
  roots := #[`Test.Extended]

@[default_target]
lean_exe casbin where
  root := `Main

@[default_target, test_driver]
lean_exe casbin_test where
  root := `Test.Main
