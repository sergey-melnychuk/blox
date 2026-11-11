package wtf.oxff.blox

import android.app.Application
import wtf.oxff.blox.keystore.Keystore
import wtf.oxff.blox.store.Answers
import wtf.oxff.blox.store.AuditLog
import wtf.oxff.blox.store.Connections
import wtf.oxff.blox.store.Settings
import wtf.oxff.blox.vault.SignerVault

class BloxApp : Application() {
    lateinit var vault: SignerVault
        private set
    lateinit var settings: Settings
        private set
    lateinit var connections: Connections
        private set
    lateinit var answers: Answers
        private set
    lateinit var audit: AuditLog
        private set
    lateinit var keystore: Keystore
        private set

    override fun onCreate() {
        super.onCreate()
        vault = SignerVault(this)
        settings = Settings(this)
        connections = Connections(this)
        answers = Answers(this)
        audit = AuditLog(this)
        keystore = Keystore(this)
    }
}
