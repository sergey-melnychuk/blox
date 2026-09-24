package wtf.oxff.blox.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.vault.SeedVault

@Composable
fun Home(app: BloxApp, onScan: () -> Unit, onReset: () -> Unit) {
    val level = remember { runCatching { app.vault.securityLevel() }.getOrNull() }
    var confirmReset by remember { mutableStateOf(false) }
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Blox", style = MaterialTheme.typography.headlineMedium)
        Text(
            when (level) {
                SeedVault.SecurityLevel.STRONGBOX -> "Key protected by StrongBox"
                SeedVault.SecurityLevel.TEE -> "Key protected by the secure environment (TEE)"
                SeedVault.SecurityLevel.SOFTWARE -> "⚠ Key protected by software only on this device"
                null -> ""
            },
            style = MaterialTheme.typography.bodySmall,
        )
        app.accounts.addresses().forEachIndexed { i, a ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Account ${i + 1}", style = MaterialTheme.typography.labelMedium)
                    Text(a, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        Button(onClick = onScan, modifier = Modifier.fillMaxWidth().height(64.dp)) { Text("Scan") }
        Text(
            "Run a signing command on your computer, then scan the QR code it shows.",
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(24.dp))
        if (!confirmReset) {
            TextButton(onClick = { confirmReset = true }) { Text("Remove keys from this phone…") }
        } else {
            Text("This deletes the key from this phone. You can only get it back with your recovery phrase.")
            Button(onClick = {
                app.vault.wipe()
                app.accounts.clear()
                onReset()
            }) { Text("Delete key") }
            TextButton(onClick = { confirmReset = false }) { Text("Cancel") }
        }
    }
}
