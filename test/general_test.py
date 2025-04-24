import string
import traceback

class GeneralTest:

        def __init__(self, domain_name, skip_list=None, run_list=None):
                self.tests = {}
                self.skip_tests_list = [] if skip_list is None else skip_list
                self.run_tests_list = run_list
                self.domain_name = domain_name
                self.default_test_id = 1

        def print(self, color=True):
                REDC = "\033[91m"
                GREENC = "\033[92m"
                YELLOYC = "\033[93m"
                CYANC = "\033[96m"
                NOC = "\033[0m"

                if not color:
                        REDC = ""
                        GREENC = ""
                        NOC = ""

                print("=========== %s domain report ============"
                      % (self.domain_name,))

                result_table = {
                        True: "%sPASS%s" % (GREENC, NOC)
                        , False: "%sFAILED%s" % (REDC, NOC)
                        , "NA": "%sNA%s" % (CYANC, NOC)
                        , None: "%sSKIPPED%s" % (YELLOYC, NOC)
                }

                failed = 0
                skipped = 0
                not_applicable = 0
                for (test_id, test_info) in self.tests.items():
                        failed += 1 if test_info["result"] == False else 0
                        skipped += 1 if test_info["result"] is None else 0
                        not_applicable += 1 if test_info["result"] is "NA" else 0
                        print("%s: %s" % (test_id, result_table[test_info["result"]]))

                if failed == 0:
                        print("\nOVERAL RESULT: %sall %d tests green%s%s%s\n"
                              % (GREENC, len(self.tests.keys()) - skipped, NOC
                                 , "" if skipped == 0 else
                                   ("(%sskipped %d%s)" % (YELLOYC, skipped, NOC))
                                 , "" if not_applicable == 0 else
                                   ("(%sNA %d%s)" % (CYANC, not_applicable, NOC))
                                ))
                else:
                        print("\nOVERAL RESULT: %s%d failed%s of total %d%s\n"
                              % (REDC, failed, NOC, len(self.tests.keys()) - skipped
                                 , "" if skipped == 0 else
                                   ("(%sskipped %d%s)" % (YELLOYC, skipped, NOC))
                                 , "" if not_applicable == 0 else
                                   ("(%sNA %d%s)" % (CYANC, not_applicable, NOC))
                                ))

                print("========== %s domain report END ========="
                      % (self.domain_name,))

                if failed == 0 and skipped == 0:
                    print("%s: PASS" % (self.domain_name,))

        def append_report(self, test_id, test_result):
                self.tests[test_id] = { "id": test_id, "result": test_result }

        def failed_count(self):
                failed = 0
                for (test_id, test_info) in self.tests.items():
                        failed += 1 if test_info["result"] == False else 0
                return failed

        # Launches the test given by the callable @test_sequencescription:
        #       iccom sk -> send data to iccom
        # @test_sequence can run in two modes
        #   * provides the test info dict
        #   * run the actual test sequence and throw in case of any errors
        def test(self, test_sequence, params):
            test_id = None
            test_descr = None
            try:
                test_info = test_sequence(params, get_test_info=True)
                
                test_id = test_info["test_id"]
                test_descr = test_info["test_description"]
                test_applicable = True
                if "applicable" in test_info:
                    test_applicable = test_info["applicable"]

                print("======== TEST: %s ========" % (test_id,))

                if not test_applicable:
                    print("%s: NA" % (test_id,))
                    self.append_report(test_id, "NA")
                    return

                if ((test_id in self.skip_tests_list)
                        or (self.run_tests_list is not None and test_id not in self.run_tests_list)):
                    print("%s: SKIPPED" % (test_id,))
                    self.append_report(test_id, None)
                    return

                test_sequence(params)

                print("%s: PASS" % (test_id,))
                self.append_report(test_id, True)

            except Exception as e:
                if test_id is None:
                      test_id = self.default_test_id
                      self.default_test_id += 1

                print("%s: FAILED: %s (test description: %s)"
                      % (str(test_id), str(e), str(test_descr)))
                print(traceback.format_exc())

                self.append_report(test_id, False)
