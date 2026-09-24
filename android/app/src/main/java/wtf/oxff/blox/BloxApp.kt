package wtf.oxff.blox

import android.app.Application
import wtf.oxff.blox.session.SessionController
import wtf.oxff.blox.vault.AccountStore
import wtf.oxff.blox.vault.SeedVault

class BloxApp : Application() {
    lateinit var vault: SeedVault
        private set
    lateinit var accounts: AccountStore
        private set
    lateinit var session: SessionController
        private set

    override fun onCreate() {
        super.onCreate()
        vault = SeedVault(this)
        accounts = AccountStore(this)
        session = SessionController(accounts)
    }
}
