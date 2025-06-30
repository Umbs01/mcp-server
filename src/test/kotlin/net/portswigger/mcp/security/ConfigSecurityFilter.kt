package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.logging.Logging
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import io.mockk.mockk
import io.mockk.every
import kotlinx.serialization.json.*

class ConfigSecurityFilterTest {

    private lateinit var config: McpConfig
    private lateinit var api: MontoyaApi
    private lateinit var projectOptions: JsonElement
    private lateinit var usersOptions: JsonElement
    private lateinit var mockLogging: Logging
    private lateinit var persistedObject: PersistedObject
    private lateinit var projectOptionString: String
    private lateinit var usersOptionString: String

    @BeforeEach
    fun setUp() {
        api = mockk<MontoyaApi>()
        mockLogging = mockk<Logging>()
        persistedObject = mockk<PersistedObject>()
        val storage = mutableMapOf<String, Any>(
            "enabled" to true,
            "configEditingTooling" to false,
            "requireHttpRequestApproval" to true,
            "host" to "127.0.0.1",
            "_autoApproveTargets" to "",
            "port" to 9876
        )

        persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean ?: false }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg()] = secondArg<Int>()
            }
        }

        mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
        }

        projectOptionString = """
            {
                "bambda": {},
                "logger": {},
                "organiser": {},
                "project_options": {
                    "connections": {
                        "platform_authentication": {
                            "credentials": [
                                {
                                    "username": "realuser",
                                    "password": "realpass"
                                }
                            ]
                        },
                        "socks_proxy": {
                            "username": "proxyuser",
                            "password": "proxypass"
                        }
                    }
                },
                "proxy": {},
                "repeater": {},
                "sequencer": {},
                "target": {}
            }
        """.trimIndent()
        
        usersOptionString = """
            {
                "user_options": {
                    "bchecks": {},
                    "connections": {
                        "platform_authentication": {
                            "credentials": [
                                {
                                    "password": "realpass"
                                }
                            ]
                        },
                        "socks_proxy": {
                            "password": "proxypass"
                        }
                    },
                    "display": {},
                    "extender": {},
                    "intruder": {},
                    "misc": {},
                    "proxy": {},
                    "repeater": {},
                    "ssl": {}
                }
            }
        """.trimIndent()
        config = McpConfig(persistedObject, mockLogging)
    }

    @Test
    fun `test security filter on project_options `() {
        config.filterConfigCredentials = true
        val filteredProjectJson = filterProjectConfigCredentials(projectOptionString)
        val parsedJson = Json.parseToJsonElement(filteredProjectJson).jsonObject

        val credentials = parsedJson["project_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("platform_authentication")?.jsonObject
            ?.get("credentials")?.jsonArray

        val socks_proxy = parsedJson["project_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("socks_proxy")?.jsonObject

        credentials?.forEach { credential ->
            val credentialObj = credential.jsonObject
            Assertions.assertEquals("*****", credentialObj["password"]?.jsonPrimitive?.content)
        }

        socks_proxy?.let {
            Assertions.assertEquals("*****", socks_proxy["password"]?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `test security filter on user_options`() {
        config.filterConfigCredentials = true
        val filteredUserJson = filterUserConfigCredentials(usersOptionString)
        val parsedJson = Json.parseToJsonElement(filteredUserJson).jsonObject

        val credentials = parsedJson["user_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("platform_authentication")?.jsonObject
            ?.get("credentials")?.jsonArray

        val socks_proxy = parsedJson["user_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("socks_proxy")?.jsonObject

        credentials?.forEach { credential ->
            val credentialObj = credential.jsonObject
            Assertions.assertEquals("*****", credentialObj["password"]?.jsonPrimitive?.content)
        }

        socks_proxy?.let {
            Assertions.assertEquals("*****", it["password"]?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `test security filter with empty credentials on user_options`() {
        config.filterConfigCredentials = true
        val empty_user_credentials = """
            {
                "user_options": {
                    "connections": {
                        "platform_authentication": {
                            "credentials": []
                        },
                        "socks_proxy": { "password": "" }
                    }
                }
            }
        """.trimIndent()
        val filteredJson = filterUserConfigCredentials(empty_user_credentials)
        val parsedJson = Json.parseToJsonElement(filteredJson).jsonObject

        val credentials = parsedJson["user_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("platform_authentication")?.jsonObject
            ?.get("credentials")?.jsonArray

        Assertions.assertTrue(credentials.isNullOrEmpty())
    }

    @Test
    fun `test security filter with empty credentials on project_options`() {
        config.filterConfigCredentials = true
        val empty_project_credentials = """
            {
                "project_options": {
                    "connections": {
                        "platform_authentication": {
                            "credentials": []
                        },
                        "socks_proxy": { "password": "" }
                    }
                }
            }
        """.trimIndent()
        val filteredJson = filterProjectConfigCredentials(empty_project_credentials)
        val parsedJson = Json.parseToJsonElement(filteredJson).jsonObject

        val credentials = parsedJson["project_options"]?.jsonObject
            ?.get("connections")?.jsonObject
            ?.get("platform_authentication")?.jsonObject
            ?.get("credentials")?.jsonArray

        Assertions.assertTrue(credentials.isNullOrEmpty())
    }
}