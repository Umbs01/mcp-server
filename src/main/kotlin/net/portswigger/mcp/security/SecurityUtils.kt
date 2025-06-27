package net.portswigger.mcp.security

import java.awt.Frame
import net.portswigger.mcp.config.McpConfig
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class SecurityConfig(
    val user_options: Map<String, Map<String, JsonElement>>
)

/**
 * Finds the Burp Suite main frame or the largest available frame as fallback
 */
fun findBurpFrame(): Frame? {
    val burpIdentifiers = listOf("Burp Suite", "Professional", "Community", "burp")

    return Frame.getFrames().find { frame ->
        frame.isVisible && frame.isDisplayable && burpIdentifiers.any { identifier ->
            frame.title.contains(identifier, ignoreCase = true) ||
                    frame.javaClass.name.contains(identifier, ignoreCase = true) ||
                    frame.javaClass.simpleName.contains(identifier, ignoreCase = true)
        }
    } ?: Frame.getFrames()
        .filter { it.isVisible && it.isDisplayable }
        .maxByOrNull { it.width * it.height }
}

fun filterConfigCredentials(json: String): String {
    try {
        val jsonObj = Json.parseToJsonElement(json).jsonObject
        val filteredElement = filterJsonObject(jsonObj)
        return Json.encodeToString(filteredElement) 
    } catch (e: Exception) {
        return json
    }
}

fun filterJsonObject(obj: JsonObject): JsonObject {
    val filteredMap = mutableMapOf<String, JsonElement>()

    for ((key, value) in obj) {
        filteredMap[key] = when {
            value is JsonPrimitive && value.isString && isCredential(key) ->
                JsonPrimitive("*****")
            value is JsonObject -> filterJsonObject(value)
            value is JsonArray -> filterJsonArray(value)
            else -> value
        }
    }
    return JsonObject(filteredMap)
}

fun filterJsonArray(array: JsonArray): JsonArray {
    val filteredList = array.map { element ->
        when (element) {
            is JsonObject -> filterJsonObject(element)
            is JsonArray -> filterJsonArray(element)
            else -> element
        }
    }
    return JsonArray(filteredList)
}

fun isCredential(key: String): Boolean {
    val credentialKeywords = listOf(
        "password",
        "username"
    )
    return credentialKeywords.any { keyword ->
        key.lowercase().contains(keyword)
    }
}