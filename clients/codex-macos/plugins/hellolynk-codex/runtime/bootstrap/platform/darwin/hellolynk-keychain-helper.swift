// Rebuild in this directory: xcrun swiftc -O -target arm64-apple-macos13.0 -module-name HelloLynkKeychain hellolynk-keychain-helper.swift -o hellolynk-keychain-helper.bin
import AppKit
import CryptoKit
import Foundation
import Security

func fail(_ code: String) -> Never {
    FileHandle.standardError.write(Data((code + "\n").utf8))
    exit(1)
}

func requireNoGrantACL(_ path: String) {
    guard let acl = acl_get_file(path, ACL_TYPE_EXTENDED) else {
        if errno == ENOENT { return } // A first write creates the file with mode 0600.
        fail("macos_vault_acl_unavailable")
    }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    var entry: acl_entry_t?
    var selector = ACL_FIRST_ENTRY
    while acl_get_entry(acl, Int32(selector.rawValue), &entry) == 0 {
        var tag = ACL_UNDEFINED_TAG
        guard acl_get_tag_type(entry, &tag) == 0, tag == ACL_EXTENDED_DENY else {
            fail("macos_vault_acl_invalid")
        }
        selector = ACL_NEXT_ENTRY
    }
}

// The caller verifies the release path's ancestors and package hashes. Walk
// with lstat so a symlink or hard link cannot redirect a permission change.
func secureRelease(_ path: String, verifyOnly: Bool) {
    var pending = [path]
    while let entry = pending.popLast() {
        var st = stat()
        guard lstat(entry, &st) == 0, st.st_uid == getuid() else { fail("macos_vault_release_invalid") }
        let type = st.st_mode & S_IFMT
        guard type == S_IFDIR || (type == S_IFREG && st.st_nlink == 1) else { fail("macos_vault_release_invalid") }
        let mode: mode_t = type == S_IFDIR || entry.hasSuffix(".bin") ? 0o700 : 0o600
        if (st.st_mode & 0o7777) != mode {
            guard !verifyOnly, chmod(entry, mode) == 0 else { fail("macos_vault_release_permissions_invalid") }
        }
        requireNoGrantACL(entry)
        if type == S_IFDIR {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: entry) else { fail("macos_vault_release_invalid") }
            pending.append(contentsOf: names.map { entry + "/" + $0 })
        }
    }
}

func masterKey(_ root: String, create: Bool) -> Data {
    let account = SHA256.hash(data: Data(root.utf8)).map { String(format: "%02x", $0) }.joined()
    let base: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.hellolynk.codex.macos-vault.v1",
        kSecAttrAccount as String: account
    ]
    var lookup = base
    lookup[kSecReturnData as String] = true
    lookup[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(lookup as CFDictionary, &result)
    if status == errSecSuccess {
        guard let key = result as? Data, key.count == 32 else { fail("macos_vault_key_invalid") }
        return key
    }
    guard status == errSecItemNotFound else { fail("macos_keychain_access_\(abs(Int(status)))") }
    guard create else { fail("macos_vault_key_missing") }
    let key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    var add = base
    add[kSecValueData as String] = key
    add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let inserted = SecItemAdd(add as CFDictionary, nil)
    if inserted == errSecDuplicateItem { return masterKey(root, create: false) }
    guard inserted == errSecSuccess else { fail("macos_keychain_access_\(abs(Int(inserted)))") }
    return key
}

func nativeConfirmation() {
    let raw = FileHandle.standardInput.readDataToEndOfFile()
    guard raw.count <= 20480 * 6 + 8192,
          var v = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any],
          let body = v["displayText"] as? String, !body.isEmpty, body.utf8.count <= 20480,
          let encoded = v["hmacKey"] as? String, encoded.count == 43,
          let key = Data(base64Encoded: encoded.replacingOccurrences(of: "-", with: "+")
              .replacingOccurrences(of: "_", with: "/") + "="), key.count == 32,
          let recipient = v["recipientHelloLynkId"] as? String,
          v["contract"] as? String == "hellolynk-native-human-confirmation-v1",
          v["textDigest"] as? String == SHA256.hash(data: Data(body.utf8)).map({ String(format: "%02x", $0) }).joined()
    else { fail("human_confirmation_request_invalid") }

    var fields = ["contract", "actionId", "decision", "principalId", "delegateId", "hostInstallationId",
                  "adapterId", "adapterInstanceId", "hostGeneration", "recipientHelloLynkId"]
    var label = "收件人：" + recipient
    if v["recipientDelegateId"] != nil || v["recipientInstanceDisplayName"] != nil {
        guard let name = v["recipientInstanceDisplayName"] as? String, !name.isEmpty, name.utf8.count <= 512,
              name.range(of: #"[\x00-\x1F\x7F-\x9F\u2028\u2029\u202A-\u202E\u2066-\u2069]"#, options: .regularExpression) == nil,
              v["recipientDelegateId"] is String else { fail("human_confirmation_request_invalid") }
        fields += ["recipientDelegateId", "recipientInstanceDisplayName"]
        label += "\n目标 AI：" + name
    }
    fields += ["clientMessageId", "textDigest", "createdAtMs", "expiresAtMs", "challenge"]
    var expected = Set(fields)
    expected.remove("decision")
    expected.formUnion(["displayText", "hmacKey"])
    guard expected == Set(v.keys) else { fail("human_confirmation_request_invalid") }
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    let dialog = NSAlert()
    dialog.messageText = "是否允许 HelloLynk 发送以下文本？"
    dialog.informativeText = label
    dialog.addButton(withTitle: "取消")
    dialog.addButton(withTitle: "批准发送")
    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 500, height: 230))
    scroll.hasVerticalScroller = true
    let view = NSTextView(frame: scroll.contentView.bounds)
    view.isEditable = false
    view.isRichText = false
    view.isVerticallyResizable = true
    view.autoresizingMask = [.width]
    view.textContainer?.widthTracksTextView = true
    view.string = body
    scroll.documentView = view
    dialog.accessoryView = scroll
    v["decision"] = dialog.runModal() == .alertSecondButtonReturn ? "approve" : "cancel"
    let message = fields.map { field -> String in
        if let text = v[field] as? String { return text }
        if ["createdAtMs","expiresAtMs"].contains(field), let n = v[field] as? NSNumber { return n.stringValue }
        fail("human_confirmation_request_invalid")
    }.joined(separator: "\n")
    let proof = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: key))
    v["proof"] = proof.map { String(format: "%02x", $0) }.joined()
    for field in ["hmacKey", "challenge", "displayText"] { v.removeValue(forKey: field) }
    guard let output = try? JSONSerialization.data(withJSONObject: v) else { fail("human_confirmation_response_invalid") }
    FileHandle.standardOutput.write(output)
}

let args = Array(CommandLine.arguments.dropFirst())
if args == ["confirm"] { nativeConfirmation() }
else if args.count == 3, args[0] == "key", args[1].hasPrefix("/"), ["load","create"].contains(args[2]) {
    requireNoGrantACL(args[1])
    requireNoGrantACL(args[1] + "/protected-v1.sqlite")
    let key = masterKey(args[1], create: args[2] == "create")
    FileHandle(fileDescriptor: 3, closeOnDealloc: false).write(key)
} else if args.count == 2, ["verify-tree", "secure-tree"].contains(args[0]), args[1].hasPrefix("/") {
    secureRelease(args[1], verifyOnly: args[0] == "verify-tree")
} else if args.count == 2, args[0] == "verify-acl", args[1].hasPrefix("/") {
    requireNoGrantACL(args[1])
} else { fail("macos_vault_helper_arguments_invalid") }
