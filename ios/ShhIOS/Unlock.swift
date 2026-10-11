import Foundation
import LocalAuthentication

enum OwnerGate {
    static func unlock() async throws {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw error ?? KeyError.unreadable
        }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock the vault key.") { ok, err in
                if ok {
                    cont.resume()
                } else {
                    cont.resume(throwing: err ?? KeyError.unreadable)
                }
            }
        }
    }
}
