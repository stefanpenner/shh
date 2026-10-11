import XCTest
@testable import ShhIOS

final class PeopleTests: XCTestCase {
    private let age = "age1" + String(repeating: "a", count: 58)

    func testGithubNameOpensTheProfile() {
        let person = present(name: "https://github.com/stefanpenner", key: age, youKey: age)
        XCTAssertEqual(person.title, "stefanpenner")
        XCTAssertEqual(person.detail, "GitHub")
        XCTAssertEqual(person.url, URL(string: "https://github.com/stefanpenner"))
        XCTAssertTrue(person.you)
    }

    func testGithubNameRejectsADirtyURL() {
        let dirty = [
            "https://github.com/stefanpenner/keys",
            "https://github.com/stefanpenner/",
            "https://github.com/stefanpenner?x=1",
            "http://github.com/stefanpenner",
            "https://github.com.evil/stefanpenner",
            "https://github.com/-bad",
            "https://github.com/a-",
            "stefanpenner",
        ]
        for name in dirty {
            let person = present(name: name, key: age, youKey: "")
            XCTAssertNil(person.url, name)
        }
    }

    func testAgeNameStaysOnTheDevice() {
        let person = present(name: age, key: age, youKey: "")
        XCTAssertEqual(person.title, "age1aaaaaa…aaaa")
        XCTAssertEqual(person.detail, "Age key")
        XCTAssertNil(person.url)
        XCTAssertFalse(person.you)
    }

    func testDirectoryMarksWhoIsOnTheFile() {
        let file = [Party(name: "https://github.com/example", key: age)]
        let known = file + [
            Party(name: "https://github.com/alice", key: "age1" + String(repeating: "b", count: 58)),
            Party(name: "stef-yubikey", key: "age1" + String(repeating: "c", count: 58)),
        ]
        let rows = roster(file: file, known: known, youKey: age)
        XCTAssertEqual(rows.map(\.person.title), ["example", "alice", "stef-yubikey"])
        XCTAssertEqual(rows.map(\.onFile), [true, false, false])
        XCTAssertEqual(rows[0].person.url, URL(string: "https://github.com/example"))
        XCTAssertTrue(rows[0].person.you)
        XCTAssertNil(rows[2].person.url)
        XCTAssertEqual(statusLine(you: true, onFile: true, showMembership: true), "Your key · On this file")
        XCTAssertEqual(statusLine(you: false, onFile: false, showMembership: true), "Not on this file")
        XCTAssertNil(statusLine(you: false, onFile: true, showMembership: false))
    }

    func testEmptyDirectoryUsesTheFile() {
        let file = [Party(name: "stef-yubikey", key: age)]
        let rows = roster(file: file, known: [], youKey: "")
        XCTAssertEqual(rows.map(\.person.title), ["stef-yubikey"])
        XCTAssertEqual(rows.map(\.onFile), [true])
    }

    func testShhUserDropsTheScheme() {
        let person = present(name: "shh-user://ci", key: age, youKey: "")
        XCTAssertEqual(person.title, "ci")
        XCTAssertEqual(person.detail, "user")
        XCTAssertNil(person.url)
    }

    func testNamedKeyKeepsTheLabel() {
        let person = present(name: "stef-yubikey", key: age, youKey: "other")
        XCTAssertEqual(person.title, "stef-yubikey")
        XCTAssertEqual(person.detail, "Age key")
        XCTAssertNil(person.url)
        XCTAssertFalse(person.you)
    }
}
