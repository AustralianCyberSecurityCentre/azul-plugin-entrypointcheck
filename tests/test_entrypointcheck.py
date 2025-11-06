"""
entrypointcheck test suite
==========================
Test the entrypointcheck plugin

"""

from azul_runner import FV, Event, Filepath, JobResult, State, Uri, test_template

from azul_plugin_entrypointcheck.main import AzulPluginEntryPointCheck


class TestExecuteEntrypointCheck(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginEntryPointCheck

    def test_on_valid_entrypoint(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "80c8984124c10649e5d4f64d1204d6375ee8a95203e0c91da3763d80381e1f93",
                        "Malcious Windows 32EXE, dropper, malware family apmu.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.COMPLETED_EMPTY)),
        )

    def test_on_invalid_entrypoint_section(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "fbd635cd48087d967654eb006352c8d2e62d05b0478bd086e75ee2e63ea38afb",
                        "Malicious Windows 32EXE, trojan, threat actor APT40.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="fbd635cd48087d967654eb006352c8d2e62d05b0478bd086e75ee2e63ea38afb",
                        features={"tag": [FV("Entrypoint points to nonstandard section")]},
                    )
                ],
            ),
        )

    def test_on_entrypoint_last_section(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "2c5dd8a64437cb2dd4b6747139c61d2d7f53ab3ddedbf22df3cb01bae170715b",
                        "Malicious Windows 32EXE, trojan, malware family genome.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="2c5dd8a64437cb2dd4b6747139c61d2d7f53ab3ddedbf22df3cb01bae170715b",
                        features={
                            "tag": [FV("Entrypoint is last section"), FV("Entrypoint points to nonstandard section")]
                        },
                    )
                ],
            ),
        )

    def test_on_entrypoint_invalid(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "068a94265c45add5ff31a4e52f47d43c8e96480d3b8dcd5d9d2888de6a51c1e1",
                        "PE with an entrypoint outside of the legal range.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="068a94265c45add5ff31a4e52f47d43c8e96480d3b8dcd5d9d2888de6a51c1e1",
                        features={"tag": [FV("Entrypoint outside valid range")]},
                    )
                ],
            ),
        )

    def test_on_entrypoint_invalid_pefile(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "e8e1600fd031734da7c3e0a59d754e7132b49e06c3356b14edef16955659ef2f", "Win32 DLL"
                    ),
                )
            ]
        )

        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.COMPLETED_EMPTY)),
        )

    def test_on_no_sections_parsed(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "1aadae3bcf5cc68b86850039f6aeabd51f7dabbb818db68c05a54a8fe9a3fef3",
                        "Malicious Windows 32EXE, malware family poisonivy.",
                    ),
                )
            ]
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED_WITH_ERRORS, message="No sections parsed from PE File"),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="1aadae3bcf5cc68b86850039f6aeabd51f7dabbb818db68c05a54a8fe9a3fef3",
                        features={"malformed": [FV("No sections parsed from PE File")]},
                    )
                ],
            ),
        )
