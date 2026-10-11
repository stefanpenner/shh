import SwiftUI
import UIKit

struct RootView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = VaultModel()

    var body: some View {
        NavigationStack {
            Group {
                if model.unlocked {
                    VaultPage(model: model)
                } else {
                    LockedPage(model: model)
                }
            }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background {
                model.lock()
            }
        }
        .onOpenURL { url in
            model.openHanded(url)
        }
        .onAppear {
            #if DEBUG
            if ProcessInfo.processInfo.arguments.contains("-openSample") {
                model.openSample()
            }
            #endif
        }
    }
}

struct LockedPage: View {
    @ObservedObject var model: VaultModel

    var body: some View {
        ContentUnavailableView {
            Label("Locked", systemImage: "lock.fill")
        } description: {
            Text(model.handedName.isEmpty ? "Unlock to read a vault." : "Unlock to open \(model.handedName).")
        } actions: {
            Button("Unlock") {
                Task { await model.unlock() }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            #if DEBUG
            Button("Open sample") {
                model.openSample()
            }
            #endif
            if !model.failure.isEmpty {
                Text(model.failure)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }
        }
        .navigationTitle("shh")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct VaultPage: View {
    @ObservedObject var model: VaultModel
    @State private var copiedPublic = false

    var body: some View {
        Group {
            if model.fileName.isEmpty {
                emptyFile
            } else {
                openFile
            }
        }
        .navigationTitle(model.fileName.isEmpty ? "shh" : model.fileName)
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: model.unlocked) { _, open in
            if !open {
                copiedPublic = false
            }
        }
        .toolbar {
            if !model.fileName.isEmpty {
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        model.picking = true
                    } label: {
                        Image(systemName: "folder")
                    }
                    .accessibilityLabel("Open .env.enc")
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    model.lock()
                } label: {
                    Image(systemName: "lock")
                }
                .accessibilityLabel("Lock")
            }
        }
        .fileImporter(isPresented: $model.picking, allowedContentTypes: [.shhVault, .data]) { result in
            switch result {
            case .success(let url):
                model.openFile(url)
            case .failure(let error):
                model.failure = error.localizedDescription
            }
        }
    }

    private var emptyFile: some View {
        ContentUnavailableView {
            Label("No file", systemImage: "doc")
        } description: {
            Text("Open an .env.enc file.")
        } actions: {
            Button("Open .env.enc") {
                model.picking = true
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            Text("Your key is unlocked.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Text(present(name: model.recipient, key: model.recipient, youKey: model.recipient).title)
                .font(.body.monospaced())
                .privacySensitive()
            Button(copiedPublic ? "Copied" : "Copy public key") {
                let staged = publicPasteboard(key: model.recipient)
                UIPasteboard.general.setItems(staged.items, options: staged.options)
                copiedPublic = true
            }
            .buttonStyle(.bordered)
            if !model.failure.isEmpty {
                Text(model.failure)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }
        }
    }

    private var openFile: some View {
        List {
            failureLine
            recipientsTable
            secretsTable
        }
        .listStyle(.plain)
        .searchable(text: $model.query, prompt: "Filter names")
        .autocorrectionDisabled()
        .textInputAutocapitalization(.never)
    }

    @ViewBuilder
    private var failureLine: some View {
        if !model.failure.isEmpty {
            Section {
                Text(model.failure)
                    .font(.body.monospaced())
                    .foregroundStyle(.red)
                    .listRowSeparator(.hidden)
            }
        }
    }

    private var recipientsTable: some View {
        let rows = roster(file: model.parties, known: [], youKey: model.recipient)
        return Section {
            ForEach(rows, id: \.person.key) { row in
                PersonRow(
                    person: row.person,
                    status: statusLine(you: row.person.you, onFile: row.onFile, showMembership: false)
                )
                .listRowSeparator(.hidden)
            }
        } header: {
            tableHeader("recipients")
        }
    }

    private var secretsTable: some View {
        Section {
            if model.shown.isEmpty {
                Text("No matching name.")
                    .font(.body.monospaced())
                    .foregroundStyle(.secondary)
                    .listRowSeparator(.hidden)
            } else {
                ForEach(model.shown, id: \.self) { name in
                    SecretLine(name: name, model: model)
                        .listRowSeparator(.hidden)
                }
            }
        } header: {
            tableHeader("secrets")
        }
    }

    private func tableHeader(_ name: String) -> some View {
        Text("[\(name)]")
            .font(.subheadline.monospaced())
            .foregroundStyle(.secondary)
            .textCase(nil)
            .accessibilityAddTraits(.isHeader)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 8)
    }
}

private struct FileLine<Value: View>: View {
    var name: String
    @ViewBuilder var value: () -> Value

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(name)
                .font(.body.monospaced())
                .foregroundStyle(.primary)
                .layoutPriority(1)
            Text("=")
                .font(.body.monospaced())
                .foregroundStyle(.tertiary)
            value()
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 4)
    }
}

private struct SecretLine: View {
    var name: String
    @ObservedObject var model: VaultModel

    private var open: Bool {
        model.revealedName == name && !model.revealedValue.isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            FileLine(name: name) {
                if open {
                    Text(model.revealedValue)
                        .font(.body.monospaced())
                        .foregroundStyle(.primary)
                        .privacySensitive()
                        .textSelection(.disabled)
                } else {
                    Button("Tap to view") {
                        model.reveal(name)
                    }
                    .font(.body.monospaced())
                    .buttonStyle(.plain)
                    .foregroundStyle(.tint)
                    .accessibilityLabel("Tap to view \(name)")
                }
            }
            if open {
                HStack(spacing: 8) {
                    Button("Copy") {
                        model.copyRevealed()
                    }
                    Button("Hide") {
                        model.hide()
                    }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                if model.copied {
                    Text("The clipboard clears in 30 seconds.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .privacySensitive()
    }
}

private struct PersonRow: View {
    var person: Person
    var status: String?

    var body: some View {
        FileLine(name: person.title) {
            HStack(spacing: 8) {
                if let url = person.url {
                    Link(destination: url) {
                        HStack(spacing: 4) {
                            Text("GitHub")
                            Image(systemName: "arrow.up.right")
                                .font(.caption.weight(.semibold))
                        }
                    }
                    .accessibilityLabel("Open \(person.title) on GitHub")
                } else {
                    Text(person.detail)
                        .foregroundStyle(.secondary)
                }
                if let status {
                    Text(status)
                        .foregroundStyle(.secondary)
                }
            }
            .font(.body.monospaced())
        }
        .contextMenu {
            Button("Copy public key") {
                let staged = publicPasteboard(key: person.key)
                UIPasteboard.general.setItems(staged.items, options: staged.options)
            }
        }
    }
}
