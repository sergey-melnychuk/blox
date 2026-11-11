package wtf.oxff.blox.ui

import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Badge
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.vault.SignerInfo
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

    BloxScreen(
        title = "Blox",
        actions = { IconButton(onClick = onSettings) { Icon(Icons.Filled.Settings, contentDescription = "Settings") } },
        bottom = { PrimaryButton("Scan", onScan) },
    ) {
        if (status.isNotEmpty()) Hint(status)
        notice?.let { Notice(it, onClick = { app.keystore.dismissNotice() }) }

        val groups = pending.groupBy { it.connectionId }.toList()
        Section("Requests") {
            if (groups.isEmpty()) {
                Item("None")
            }
            Rows(groups) { (connectionId, items) ->
                val first = items.first()
                val signer = signers.firstOrNull { it.id == first.signerId }
                Item(
                    first.label,
                    supporting = listOfNotNull(plural(items.size, "request"), signer?.label).joinToString(" · "),
                    trailing = { Badge { Text("${items.size}") } },
                    onClick = { onReview(connectionId) },
                )
            }
        }

        Section("Signers") {
            Rows(signers) { s ->
                Item(
                    s.label,
                    supporting = signerFacts(s, app.vault.securityLevel(s.id), connections.count { it.signerId == s.id }),
                    overline = shortAddress(s.address),
                    trailing = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                    onClick = { onSigner(s.id) },
                )
            }
            if (signers.isNotEmpty()) RowDivider()
            Item(
                "Add signer",
                headlineColor = MaterialTheme.colorScheme.primary,
                leading = { Icon(Icons.Filled.Add, contentDescription = null, Modifier.size(24.dp), tint = MaterialTheme.colorScheme.primary) },
                onClick = onAddSigner,
            )
        }
    }
}

/** "TEE · Imported · 2 connections" */
fun signerFacts(s: SignerInfo, level: SignerVault.SecurityLevel?, connections: Int): String =
    listOfNotNull(securityText(level), if (s.imported) "Imported" else null, plural(connections, "connection")).joinToString(" · ")

fun securityText(level: SignerVault.SecurityLevel?): String? = when (level) {
    SignerVault.SecurityLevel.STRONGBOX -> "StrongBox"
    SignerVault.SecurityLevel.TEE -> "TEE"
    SignerVault.SecurityLevel.SOFTWARE -> "⚠ Software only"
    null -> null
}

fun securityLong(level: SignerVault.SecurityLevel?): String = when (level) {
    SignerVault.SecurityLevel.STRONGBOX -> "StrongBox (secure chip)"
    SignerVault.SecurityLevel.TEE -> "Secure environment (TEE)"
    SignerVault.SecurityLevel.SOFTWARE -> "⚠ Software only: this phone has no secure key storage"
    null -> "Unknown"
}
