package wtf.oxff.blox.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.keystore.Keystore.ConnectState

sealed interface Screen {
    data object Home : Screen
    data object Scan : Screen
    data object AddSigner : Screen
    data class Signer(val id: String) : Screen
    data object Settings : Screen
    /** The review queue of one connection (§10.6). */
    data class Review(val connectionId: String) : Screen
}

@Composable
fun BloxRoot(activity: MainActivity, app: BloxApp) {
    var screen by remember { mutableStateOf<Screen>(if (app.vault.list().isEmpty()) Screen.AddSigner else Screen.Home) }
    val connect by app.keystore.connect.collectAsState()
    BackHandler(enabled = screen != Screen.Home && app.vault.list().isNotEmpty()) { screen = Screen.Home }

    Surface(Modifier.fillMaxSize()) {
        Box(Modifier.safeDrawingPadding()) {
            when {
                // The connect flow takes over until it's finished (§5.2).
                connect !is ConnectState.Idle -> ConnectScreen(activity, app, connect, onDone = {
                    app.keystore.cancelConnect()
                    screen = Screen.Home
                })
                else -> when (val s = screen) {
                    Screen.Home -> Home(
                        app,
                        onScan = { screen = Screen.Scan },
                        onAddSigner = { screen = Screen.AddSigner },
                        onSigner = { screen = Screen.Signer(it) },
                        onSettings = { screen = Screen.Settings },
                        onReview = { screen = Screen.Review(it) },
                    )
                    Screen.Scan -> Scanner(
                        onResult = { uri ->
                            screen = Screen.Home
                            app.keystore.scanned(uri)
                        },
                        onCancel = { screen = Screen.Home },
                    )
                    Screen.AddSigner -> AddSigner(activity, app, onDone = { screen = Screen.Home }, canCancel = app.vault.list().isNotEmpty())
                    is Screen.Signer -> SignerScreen(activity, app, s.id, onBack = { screen = Screen.Home })
                    Screen.Settings -> SettingsScreen(app, onBack = { screen = Screen.Home })
                    is Screen.Review -> ReviewScreen(activity, app, s.connectionId, onBack = { screen = Screen.Home })
                }
            }
        }
    }
}
