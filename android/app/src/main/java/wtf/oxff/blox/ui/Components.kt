package wtf.oxff.blox.ui

import android.graphics.Paint
import android.graphics.Typeface
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** The side margin of every screen. */
val Gutter = 20.dp

/** Width of the label column in [InfoRow], so values line up across rows and sections. */
val LabelWidth = 112.dp

/**
 * Every screen: a top bar, scrolling content inside one gutter, and the screen's actions pinned
 * at the bottom (above the keyboard when it's open).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BloxScreen(
    title: String,
    onBack: (() -> Unit)? = null,
    actions: @Composable RowScope.() -> Unit = {},
    bottom: (@Composable ColumnScope.() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = {
            TopAppBar(
                title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                navigationIcon = {
                    if (onBack != null) {
                        IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                    }
                },
                actions = actions,
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface),
            )
        },
        bottomBar = {
            if (bottom != null) {
                Surface(color = MaterialTheme.colorScheme.surface) {
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .windowInsetsPadding(WindowInsets.navigationBars.union(WindowInsets.ime))
                            .padding(horizontal = Gutter, vertical = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        content = bottom,
                    )
                }
            }
        },
    ) { inner ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(inner)
                .consumeWindowInsets(inner)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(start = Gutter, end = Gutter, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
            content = content,
        )
    }
}

/** A titled group of rows on one card, with an optional note under it. */
@Composable
fun Section(
    title: String? = null,
    footer: String? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        title?.let {
            Text(
                it,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
        }
        Surface(
            shape = MaterialTheme.shapes.large,
            color = MaterialTheme.colorScheme.surfaceContainerLow,
            modifier = Modifier.fillMaxWidth(),
        ) { Column(content = content) }
        footer?.let { Hint(it, Modifier.padding(horizontal = 16.dp)) }
    }
}

/** Rows of a [Section], with a divider between each two. */
@Composable
fun <T> Rows(items: List<T>, row: @Composable (T) -> Unit) {
    items.forEachIndexed { i, item ->
        if (i > 0) RowDivider()
        row(item)
    }
}

@Composable
fun RowDivider() = HorizontalDivider(Modifier.padding(horizontal = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)

/** Padding for content placed straight into a [Section] (forms, text). */
@Composable
fun SectionBody(content: @Composable ColumnScope.() -> Unit) =
    Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp), content = content)

/** A label and its value: labels share one column width, so values line up. */
@Composable
fun InfoRow(label: String, value: String, mono: Boolean = false, labelWidth: Dp = LabelWidth, onClick: (() -> Unit)? = null) {
    Row(
        Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(label, Modifier.width(labelWidth), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, fontFamily = if (mono) FontFamily.Monospace else null)
    }
}

/** A row of a [Section]: Material list item on the section's background. */
@Composable
fun Item(
    headline: String,
    modifier: Modifier = Modifier,
    supporting: String? = null,
    overline: String? = null,
    monoSupporting: Boolean = false,
    headlineColor: Color = Color.Unspecified,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
    onClick: (() -> Unit)? = null,
) {
    ListItem(
        headlineContent = { Text(headline, color = headlineColor) },
        modifier = modifier.then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier),
        overlineContent = overline?.let { { Text(it) } },
        supportingContent = supporting?.let { { Text(it, fontFamily = if (monoSupporting) FontFamily.Monospace else null) } },
        leadingContent = leading,
        trailingContent = trailing,
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
    )
}

/** Explanatory text under a heading or a field. */
@Composable
fun Hint(text: String, modifier: Modifier = Modifier) =
    Text(text, modifier, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

enum class Tone { Info, Warning, Danger }

/** A tinted card: information, a warning, or a danger that may hold a confirmation field. */
@Composable
fun Notice(
    text: String,
    tone: Tone = Tone.Info,
    title: String? = null,
    onClick: (() -> Unit)? = null,
    extra: (@Composable ColumnScope.() -> Unit)? = null,
) {
    val (bg, fg) = when (tone) {
        Tone.Info -> MaterialTheme.colorScheme.secondaryContainer to MaterialTheme.colorScheme.onSecondaryContainer
        Tone.Warning -> MaterialTheme.colorScheme.tertiaryContainer to MaterialTheme.colorScheme.onTertiaryContainer
        Tone.Danger -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
    }
    Surface(
        shape = MaterialTheme.shapes.large,
        color = bg,
        contentColor = fg,
        modifier = Modifier.fillMaxWidth().then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier),
    ) {
        Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(if (tone == Tone.Info) Icons.Filled.Info else Icons.Filled.Warning, contentDescription = null, Modifier.size(20.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                title?.let { Text(it, style = MaterialTheme.typography.titleSmall) }
                Text(text, style = MaterialTheme.typography.bodyMedium)
                extra?.invoke(this)
            }
        }
    }
}

/** A text field that always spans the width, so fields and buttons line up. */
@Composable
fun Field(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    singleLine: Boolean = true,
    minLines: Int = 1,
    mono: Boolean = false,
    supporting: String? = null,
    isError: Boolean = false,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier.fillMaxWidth(),
        label = { Text(label) },
        singleLine = singleLine,
        minLines = minLines,
        isError = isError,
        supportingText = supporting?.let { { Text(it) } },
        keyboardOptions = keyboardOptions,
        textStyle = if (mono) LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace) else LocalTextStyle.current,
    )
}

private val ButtonHeight = 52.dp

@Composable
fun PrimaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, danger: Boolean = false) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.fillMaxWidth().heightIn(min = ButtonHeight),
        colors = if (danger) {
            ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError)
        } else {
            ButtonDefaults.buttonColors()
        },
    ) { Text(text) }
}

@Composable
fun SecondaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    OutlinedButton(onClick = onClick, enabled = enabled, modifier = modifier.fillMaxWidth().heightIn(min = ButtonHeight)) { Text(text) }
}

/** Two buttons side by side, the main one on the right. */
@Composable
fun ButtonPair(
    secondary: String,
    onSecondary: () -> Unit,
    primary: String,
    onPrimary: () -> Unit,
    primaryEnabled: Boolean = true,
    secondaryEnabled: Boolean = true,
    danger: Boolean = false,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        SecondaryButton(secondary, onSecondary, Modifier.weight(1f), secondaryEnabled)
        PrimaryButton(primary, onPrimary, Modifier.weight(1f), primaryEnabled, danger)
    }
}

@Composable
fun SmallTextButton(text: String, onClick: () -> Unit, color: Color = Color.Unspecified) {
    TextButton(onClick = onClick) { Text(text, color = color) }
}

/** A spinner with a line of text. */
@Composable
fun Busy(text: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 24.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Center) {
        CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.5.dp)
        Spacer(Modifier.width(16.dp))
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}

/**
 * A recovery phrase (UTF-8 bytes, words separated by single spaces) in two columns, 1–6 and
 * 7–12. Drawn one character at a time from the bytes, so no `String` of a word or of the
 * phrase is ever made (it couldn't be wiped), and the text layout cache only ever sees single
 * letters. Not exposed to accessibility services, on purpose.
 */
@Composable
fun SecretPhrase(phrase: ByteArray) {
    val words = remember(phrase) { wordRanges(phrase) }
    val rows = (words.size + 1) / 2
    val style = MaterialTheme.typography.titleMedium
    val ink = MaterialTheme.colorScheme.onSurface.toArgb()
    val dim = MaterialTheme.colorScheme.onSurfaceVariant.toArgb()
    val density = LocalDensity.current
    val paint = remember(density, style) {
        Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.MONOSPACE
            textSize = with(density) { style.fontSize.toPx() }
        }
    }
    val rowHeight = 36.dp
    Canvas(Modifier.fillMaxWidth().padding(16.dp).height(rowHeight * rows)) {
        val one = CharArray(1)
        val advance = paint.measureText("m")
        val rowPx = rowHeight.toPx()
        val baseline = (rowPx - paint.fontMetrics.ascent - paint.fontMetrics.descent) / 2
        words.forEachIndexed { n, range ->
            var x = (n / rows) * size.width / 2
            val y = (n % rows) * rowPx + baseline
            paint.color = dim
            drawContext.canvas.nativeCanvas.drawText("${n + 1}".padStart(2), x, y, paint)
            x += advance * 3.5f
            paint.color = ink
            for (i in range) {
                one[0] = (phrase[i].toInt() and 0xff).toChar()
                drawContext.canvas.nativeCanvas.drawText(one, 0, 1, x, y, paint)
                x += advance
            }
        }
        one[0] = ' '
    }
}

/** Byte ranges of the space-separated words. */
fun wordRanges(phrase: ByteArray): List<IntRange> {
    val out = mutableListOf<IntRange>()
    var start = 0
    for (i in 0..phrase.size) {
        if (i == phrase.size || phrase[i] == ' '.code.toByte()) {
            if (i > start) out += start until i
            start = i + 1
        }
    }
    return out
}

/** Whether `typed` is the word at `range`, compared without making a String of the word. */
fun wordMatches(phrase: ByteArray, range: IntRange, typed: String): Boolean =
    typed.length == range.count() && range.withIndex().all { (k, i) -> (phrase[i].toInt() and 0xff).toChar() == typed[k] }

/** `0x1234…abcd`, for lists; screens about one account show it whole. */
fun shortAddress(a: String): String = if (a.length > 14) "${a.take(6)}…${a.takeLast(4)}" else a

fun plural(n: Int, word: String): String = "$n $word${if (n == 1) "" else "s"}"
