// Wickey presence helper (macOS). A Secure Enclave P-256 key whose every use needs the human to
// approve a system prompt (Touch ID, login password or Apple Watch). The key never leaves the chip;
// its handle is stored in <dir>/key.handle. The 32-byte secret is
// SHA-256(ECDH(SE key, peer public key stored in <dir>/peer.key)). No Keychain item is created.
//
//   probe                              never prompts
//   create <dir>                       never prompts
//   use <dir> --reason "<text>" [--no-ui]   prompts (or fails with -1004 under --no-ui)
//   delete <dir>                       never prompts
//
// JSON on stdout, exit 0 on success and 1 otherwise. The secret appears only in the `use` result.
import Foundation
import CryptoKit
import LocalAuthentication
import Security

let args = Array(CommandLine.arguments.dropFirst())

func emit(_ obj: [String: Any], code: Int32) -> Never {
  let data = (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])) ?? Data("{}".utf8)
  FileHandle.standardOutput.write(data)
  FileHandle.standardOutput.write(Data("\n".utf8))
  exit(code)
}

func fail(_ error: Error) -> Never {
  let ns = error as NSError
  emit(["ok": false, "code": ns.code, "message": ns.localizedDescription], code: 1)
}

guard let cmd = args.first else { emit(["ok": false, "code": 2, "message": "usage: probe|create|use|delete"], code: 1) }

if cmd == "probe" {
  if SecureEnclave.isAvailable { emit(["available": true], code: 0) }
  emit(["available": false, "reason": "no-secure-enclave"], code: 1)
}

guard args.count >= 2 else { emit(["ok": false, "code": 2, "message": "missing <dir>"], code: 1) }
let dir = URL(fileURLWithPath: args[1])
let handleURL = dir.appendingPathComponent("key.handle")
let peerURL = dir.appendingPathComponent("peer.key")

func writePrivate(_ data: Data, to url: URL) throws {
  try data.write(to: url, options: .atomic)
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}

do {
  switch cmd {
  case "create":
    guard SecureEnclave.isAvailable else { emit(["ok": false, "code": 3, "message": "no Secure Enclave"], code: 1) }
    var err: Unmanaged<CFError>?
    // userPresence: biometry or password, so adding a finger later does not destroy the key.
    guard let ac = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &err)
    else { throw err!.takeRetainedValue() as Error }
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
    let peer = P256.KeyAgreement.PrivateKey() // only its public half is kept
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    try writePrivate(key.dataRepresentation, to: handleURL)
    try writePrivate(peer.publicKey.rawRepresentation, to: peerURL)
    emit(["ok": true], code: 0)
  case "use":
    guard let i = args.firstIndex(of: "--reason"), i + 1 < args.count else {
      emit(["ok": false, "code": 2, "message": "missing --reason"], code: 1)
    }
    let ctx = LAContext()
    ctx.localizedReason = args[i + 1]
    if args.contains("--no-ui") { ctx.interactionNotAllowed = true }
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
      dataRepresentation: try Data(contentsOf: handleURL), authenticationContext: ctx)
    let peer = try P256.KeyAgreement.PublicKey(rawRepresentation: try Data(contentsOf: peerURL))
    let shared = try key.sharedSecretFromKeyAgreement(with: peer)
    let secret = shared.withUnsafeBytes { Data(SHA256.hash(data: Data($0))) }
    emit(["ok": true, "secret": secret.base64EncodedString()], code: 0)
  case "delete":
    for u in [handleURL, peerURL] where FileManager.default.fileExists(atPath: u.path) {
      try FileManager.default.removeItem(at: u)
    }
    emit(["ok": true], code: 0)
  default:
    emit(["ok": false, "code": 2, "message": "unknown command"], code: 1)
  }
} catch {
  fail(error)
}
