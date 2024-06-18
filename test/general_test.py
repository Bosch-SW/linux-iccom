import string

class GeneralTest:

        def __init__(self, domain_name, skip_list=None):
                self.tests = {}
                self.skip_tests_list = [] if skip_list is None else skip_list
                self.domain_name = domain_name

        def print(self, color=True):
                REDC = "\033[91m"
                GREENC = "\033[92m"
                YELLOYC = "\033[93m"
                NOC = "\033[0m"

                if not color:
                        REDC = ""
                        GREENC = ""
                        NOC = ""

                ok = "%sPASS%s" % (GREENC, NOC)
                fail = "%sFAILED%s" % (REDC, NOC)
                skip = "%sSKIPPED%s" % (YELLOYC, NOC)

                print("=========== %s domain report ============"
                      % (self.domain_name,))

                failed = 0
                skipped = 0
                for (test_id, test_info) in self.tests.items():
                        res = (ok if test_info["result"] == True else
                               fail if test_info["result"] == False else skip)
                        failed += 1 if test_info["result"] == False else 0
                        skipped += 1 if test_info["result"] is None else 0
                        print("%s: %s" % (test_id, res))

                if failed == 0:
                        print("\nOVERAL RESULT: %sall %d tests green%s%s\n"
                              % (GREENC, len(self.tests.keys()) - skipped, NOC
                                 , "" if skipped == 0 else
                                   ("(%sskipped %d%s)" % (YELLOYC, skipped, NOC))))
                else:
                        print("\nOVERAL RESULT: %s%d failed%s of total %d%s\n"
                              % (REDC, failed, NOC, len(self.tests.keys()) - skipped
                                 , "" if skipped == 0 else
                                   ("(%sskipped %d%s)" % (YELLOYC, skipped, NOC))
                                ))

                print("========== %s domain report END ========="
                      % (self.domain_name,))

                if failed == 0 and skipped == 0:
                    print("%s: PASS" % (self.domain_name,))

        def append_report(self, test_id, test_result):
                self.tests[test_id] = { "id": test_id, "result": test_result }

        # Launches the test given by the callable @test_sequencescription:
        #       iccom sk -> send data to iccom
        # @test_sequence can run in two modes
        #   * provides the test info dict
        #   * run the actual test sequence and throw in case of any errors
        def test(self, test_sequence, params):
            try:
                test_info = test_sequence(params, get_test_info=True)
                test_id = test_info["test_id"]
                test_descr = test_info["test_description"]

                print("======== TEST: %s ========" % (test_id,))

                if test_id not in self.skip_tests_list:
                    test_sequence(params)

                    print("%s: PASS" % (test_id,))
                    self.append_report(test_id, True)
                else:
                    print("%s: SKIPPED" % (test_id,))
                    self.append_report(test_id, None)

            except Exception as e:
                print("%s: FAILED: %s (test description: %s)"
                      % (test_id, str(e), test_descr))

                self.append_report(test_id, False)
