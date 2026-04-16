package com.halalfilter.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF80CBC4),       // Teal — trust, calm
    secondary = Color(0xFF4DB6AC),
    tertiary = Color(0xFF26A69A),
    surface = Color(0xFF121212),
    background = Color(0xFF0A0A0A),
    onPrimary = Color.Black,
    onSurface = Color(0xFFE0E0E0),
    onBackground = Color(0xFFE0E0E0),
    error = Color(0xFFEF5350),
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF00897B),       // Teal 600
    secondary = Color(0xFF00796B),
    tertiary = Color(0xFF00695C),
    surface = Color(0xFFFAFAFA),
    background = Color.White,
    onPrimary = Color.White,
    onSurface = Color(0xFF212121),
    onBackground = Color(0xFF212121),
    error = Color(0xFFD32F2F),
)

@Composable
fun HalalFilterTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context)
            else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
