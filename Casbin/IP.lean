import Std.Net.Addr

namespace Casbin

private def ipNumber (s : String) : Except String (Nat × Nat) := do
  if let some addr := Std.Net.IPv4Addr.ofString s then
    return (32, addr.octets.toArray.foldl (fun n b => n * 256 + b.toNat) 0)
  if let some addr := Std.Net.IPv6Addr.ofString s then
    return (128, addr.segments.toArray.foldl (fun n b => n * 65536 + b.toNat) 0)
  throw s!"invalid IP address: {s}"

def ipMatch (input pattern : String) : Except String Bool := do
  let (width, address) ← ipNumber input
  match pattern.splitOn "/" with
  | [network] =>
    let (otherWidth, other) ← ipNumber network
    return width == otherWidth && address == other
  | [network, cidrBits] =>
    let (otherWidth, other) ← ipNumber network
    let some bits := cidrBits.toNat? | throw s!"invalid CIDR prefix: {cidrBits}"
    if bits > otherWidth then throw s!"CIDR prefix exceeds {otherWidth} bits"
    let divisor := 2 ^ (otherWidth - bits)
    return width == otherWidth && address / divisor == other / divisor
  | _ => throw s!"invalid IP pattern: {pattern}"

end Casbin
