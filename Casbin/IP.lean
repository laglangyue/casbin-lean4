import Std.Net.Addr

namespace Casbin

private def ipNumber (s : String) : Except String (Nat × Nat) := do
  if let some addr := Std.Net.IPv4Addr.ofString s then
    return (32, addr.octets.toArray.foldl (fun n b => n * 256 + b.toNat) 0)
  if let some addr := Std.Net.IPv6Addr.ofString s then
    return (128, addr.segments.toArray.foldl (fun n b => n * 65536 + b.toNat) 0)
  throw s!"invalid IP address: {s}"

private def normalize (width address : Nat) : Nat × Nat :=
  if width == 128 && address / 2 ^ 32 == 65535 then (32, address % 2 ^ 32)
  else (width, address)

def ipMatch (input pattern : String) : Except String Bool := do
  let (rawWidth, rawAddress) ← ipNumber input
  let (width, address) := normalize rawWidth rawAddress
  match pattern.splitOn "/" with
  | [network] =>
    let (rawOtherWidth, rawOther) ← ipNumber network
    let (otherWidth, other) := normalize rawOtherWidth rawOther
    return width == otherWidth && address == other
  | [network, cidrBits] =>
    let (rawOtherWidth, rawOther) ← ipNumber network
    let some bits := cidrBits.toNat? | throw s!"invalid CIDR prefix: {cidrBits}"
    if bits > rawOtherWidth then throw s!"CIDR prefix exceeds {rawOtherWidth} bits"
    let mapped := rawOtherWidth == 128 && rawOther / 2 ^ 32 == 65535 && bits ≥ 96
    let otherWidth := if mapped then 32 else rawOtherWidth
    let other := if mapped then rawOther % 2 ^ 32 else rawOther
    let bits := if mapped then bits - 96 else bits
    let divisor := 2 ^ (otherWidth - bits)
    return width == otherWidth && address / divisor == other / divisor
  | _ => throw s!"invalid IP pattern: {pattern}"

end Casbin
