package wtf.oxff.blox

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import wtf.oxff.blox.ui.BloxRoot
import wtf.oxff.blox.ui.BloxTheme

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, recording or Recents thumbnails anywhere: screens show recovery
        // phrases, QR secrets or requests (§10.7).
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
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
