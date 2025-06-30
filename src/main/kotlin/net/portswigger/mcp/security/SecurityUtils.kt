package net.portswigger.mcp.security

import java.awt.Frame
import net.portswigger.mcp.config.McpConfig
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class UserOptionsWrapper (
    var user_options: UserOptions
)

@Serializable
data class UserOptions (
    var bchecks: JsonObject,
    var connections: JsonObject,
    var display: JsonObject,
    var extender: JsonObject,
    var intruder: JsonObject,
    var misc: JsonObject,
    var proxy: JsonObject,
    var repeater: JsonObject,
    var ssl: JsonObject
)

@Serializable
data class ProjectOptions (
    var bambda: JsonObject,
    var logger: JsonObject,
    var organiser: JsonObject,
    var project_options: JsonObject,
    var proxy: JsonObject,
    var repeater: JsonObject,
    var sequencer: JsonObject,
    var target: JsonObject
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

fun filterUserConfigCredentials(jsonString: String): String {
    try {
        var wrapper = Json.decodeFromString<UserOptionsWrapper>(jsonString)
        var user_options = wrapper.user_options
        
        user_options.connections = JsonObject(user_options.connections.mapValues { (key, value) ->
            when (key) {
                "platform_authentication" -> filterPlatformAuth(value)
                "socks_proxy" -> filterSocksProxy(value)
                else -> value
            }
        })
        return Json.encodeToString(UserOptionsWrapper(user_options))
        
    } catch (e: Exception) {
        throw RuntimeException("Failed to filter user config credentials", e)
    }
}

fun filterProjectConfigCredentials(jsonString: String): String {
    try {
        var project_config = Json.decodeFromString<ProjectOptions>(jsonString)
        val connections = project_config.project_options["connections"]?.jsonObject

        if (connections != null) {
            val filtered = JsonObject(connections.mapValues { (key, value) ->
                when (key) {
                    "platform_authentication" -> filterPlatformAuth(value)
                    "socks_proxy" -> filterSocksProxy(value)
                    else -> value
                }
            })
            
            project_config.project_options = JsonObject(
                project_config.project_options.toMutableMap().apply {
                    this["connections"] = filtered
                }
            )
        }
        
        return Json.encodeToString(project_config)
    } catch (e: Exception) {
        throw RuntimeException("Failed to filter project config credentials", e)
    }
}

private fun filterPlatformAuth(value: JsonElement): JsonElement {
    val obj = value.jsonObject
    val credentials = obj["credentials"]?.jsonArray

    val filteredCredentials = credentials?.map { credentialElement ->
        val credentialObj = credentialElement.jsonObject
        JsonObject(
            credentialObj.mapValues { (key, value) ->
                when (key) {
                    "password" -> JsonPrimitive("*****")
                    else -> value
                }
            }
        )
    }
    return JsonObject(obj.toMutableMap().apply {
        this["credentials"] = JsonArray(filteredCredentials ?: emptyList())
    })
}

private fun filterSocksProxy(value: JsonElement): JsonElement {
    val obj = value.jsonObject
    return JsonObject(
        obj.mapValues { (key, value) ->
            when (key) {
                "password" -> JsonPrimitive("*****")
                else -> value
            }
        }
    )
}
