package wtf.oxff.blox.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.session.SessionController.State

@Composable
fun BloxRoot(activity: MainActivity, app: BloxApp) {
    var hasSeed by remember { mutableStateOf(app.vault.exists() && app.accounts.addresses().isNotEmpty()) }
    var scanning by remember { mutableStateOf(false) }
    val session by app.session.state.collectAsState()

    val inSession = session is State.Waiting || session is State.Reviewing || session is State.Joining
    DisposableEffect(inSession) {
        activity.keepScreenOn(inSession)
        onDispose { activity.keepScreenOn(false) }
    }

    Surface(Modifier.fillMaxSize()) {
        Box(Modifier.safeDrawingPadding()) {
            when {
                !hasSeed -> Onboarding(activity, app, onDone = { hasSeed = true })
                session !is State.Idle -> SessionScreen(activity, app, session)
                scanning -> Scanner(
                    onResult = { uri ->
                        scanning = false
                        app.session.join(uri)
                    },
                    onCancel = { scanning = false },
                )
                else -> Home(app, onScan = { scanning = true }, onReset = { hasSeed = false })
            }
        }
    }
}
