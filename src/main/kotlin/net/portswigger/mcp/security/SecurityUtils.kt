package net.portswigger.mcp.security

import java.awt.Frame
import net.portswigger.mcp.config.McpConfig
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class SecurityConfig(
    val user_options: Map<String, Map<String, JsonElement>>
)

private const val USER_OPTIONS = "user_options"
private const val PROJECT_OPTIONS = "project_options"
private const val CONNECTIONS = "connections"

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

fun filterUserConfigCredentials(jsonString: String): String {
    return filterConfigCredentials(jsonString, USER_OPTIONS)
}

fun filterProjectConfigCredentials(jsonString: String): String {
    return filterConfigCredentials(jsonString, PROJECT_OPTIONS)
}

private fun filterConfigCredentials(jsonString: String, optionsKey: String): String {
    return try {
        val json = Json.parseToJsonElement(jsonString).jsonObject
        val options = json[optionsKey]?.jsonObject ?: return jsonString
        val connections = options[CONNECTIONS]?.jsonObject ?: return jsonString
        
        val filteredConnections = connections.mapValues { (key, value) ->
            when (key) {
                "platform_authentication" -> filterPlatformAuth(value)
                "socks_proxy" -> filterSocksProxy(value)
                else -> value
            }
        }
        
        val updatedJson = json.toMutableMap()
        val updatedOptions = options.toMutableMap()
        updatedOptions[CONNECTIONS] = JsonObject(filteredConnections)
        updatedJson[optionsKey] = JsonObject(updatedOptions)
        
        Json.encodeToString(JsonObject(updatedJson))
    } catch (e: Exception) {
        jsonString
    }
}

private fun filterPlatformAuth(value: JsonElement): JsonElement {
    val obj = value.jsonObject
    val credentials = obj["credentials"]?.jsonArray ?: return value

    val filteredCredentials = credentials.map { credentialElement ->
        val credentialObj = credentialElement.jsonObject
        JsonObject(
            credentialObj.mapValues { (key, value) ->
                when (key) {
                    "username", "password" -> JsonPrimitive("*****")
                    else -> value
                }
            }
        )
    }
    return JsonObject(obj.toMutableMap().apply {
        this["credentials"] = JsonArray(filteredCredentials)
    })
}

private fun filterSocksProxy(value: JsonElement): JsonElement {
    val obj = value.jsonObject
    return JsonObject(
        obj.mapValues { (key, value) ->
            when (key) {
                "username", "password" -> JsonPrimitive("*****")
                else -> value
            }
        }
    )
}
