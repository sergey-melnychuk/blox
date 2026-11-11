package wtf.oxff.blox.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.vault.SignerVault

/** Home (§10.6): pending requests grouped by connection, signers, Scan. */
@Composable
fun Home(
    app: BloxApp,
    onScan: () -> Unit,
    onAddSigner: () -> Unit,
    onSigner: (String) -> Unit,
    onSettings: () -> Unit,
    onReview: (String) -> Unit,
) {
    val pending by app.keystore.pending.collectAsState()
    val status by app.keystore.status.collectAsState()
    val notice by app.keystore.notice.collectAsState()
    val signers = app.vault.list()
    val connections = app.connections.all()

    Column(Modifier.padding(24.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Blox", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
            TextButton(onClick = onSettings) { Text("Settings") }
        }
        if (status.isNotEmpty()) Text(status, style = MaterialTheme.typography.bodySmall)
        notice?.let {
            Card(Modifier.fillMaxWidth().clickable { app.keystore.dismissNotice() }) {
                Text(it, Modifier.padding(16.dp))
            }
        }

        // Requests, grouped by connection.
        pending.groupBy { it.connectionId }.forEach { (connectionId, items) ->
            val first = items.first()
            val signer = signers.firstOrNull { it.id == first.signerId }
            Card(
                Modifier.fillMaxWidth().clickable { onReview(connectionId) },
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
            ) {
                Column(Modifier.padding(16.dp)) {
                    Text("${first.label} · ${signer?.label ?: ""}", style = MaterialTheme.typography.titleMedium)
                    Text("${items.size} request${if (items.size == 1) "" else "s"} · Review", style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        Button(onClick = onScan, modifier = Modifier.fillMaxWidth().height(64.dp)) { Text("Scan") }
        Text("Scan the QR code a site or app shows to connect it to one of your signers.", style = MaterialTheme.typography.bodySmall)

        Spacer(Modifier.height(8.dp))
        Text("Signers", style = MaterialTheme.typography.titleMedium)
        signers.forEach { s ->
            val n = connections.count { it.signerId == s.id }
            Card(Modifier.fillMaxWidth().clickable { onSigner(s.id) }) {
                Column(Modifier.padding(16.dp)) {
                    Text(s.label, style = MaterialTheme.typography.titleSmall)
                    Text(s.address, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    Text(
                        listOfNotNull(
                            securityText(app.vault.securityLevel(s.id)),
                            "$n connection${if (n == 1) "" else "s"}",
                        ).joinToString(" · "),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
        OutlinedButton(onClick = onAddSigner, modifier = Modifier.fillMaxWidth()) { Text("Add signer") }
    }
}

fun securityText(level: SignerVault.SecurityLevel?): String? = when (level) {
    SignerVault.SecurityLevel.STRONGBOX -> "StrongBox"
    SignerVault.SecurityLevel.TEE -> "Secure environment (TEE)"
    SignerVault.SecurityLevel.SOFTWARE -> "⚠ Software only"
    null -> null
}
