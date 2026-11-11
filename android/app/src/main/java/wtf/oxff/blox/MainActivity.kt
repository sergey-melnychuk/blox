package wtf.oxff.blox

import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import wtf.oxff.blox.ui.BloxRoot
import wtf.oxff.blox.ui.BloxTheme

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        // Transparent bars: screens draw behind them and pad themselves (BloxScreen).
        enableEdgeToEdge(navigationBarStyle = SystemBarStyle.auto(Color.TRANSPARENT, Color.TRANSPARENT))
        super.onCreate(savedInstanceState)
        // No screenshots, recording or Recents thumbnails anywhere: screens show recovery
        // phrases, QR secrets or requests (§10.7).
        // (Debug builds made with -Pblox.screenshots skip it, for work on the UI.)
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) window.isNavigationBarContrastEnforced = false
        window.decorView.filterTouchesWhenObscured = true

        val app = application as BloxApp
        lifecycle.addObserver(
            LifecycleEventObserver { _, event ->
                when (event) {
                    Lifecycle.Event.ON_START -> app.keystore.onForeground()
                    Lifecycle.Event.ON_STOP -> app.keystore.onBackground()
                    else -> {}
                }
            },
        )
        setContent { BloxTheme { BloxRoot(this, app) } }
    }
}
