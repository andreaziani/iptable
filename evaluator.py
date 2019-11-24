#!/usr/bin/env python3

import os
import sys
import time
import json
import requests
import collections
import argparse

SUBMISSION_SERVER = "https://course.netsec.inf.ethz.ch//iptables"
SUBMISSION_PATH = '/submit'
RESULT_PATH = '/result'
PROCESSING_WAIT_TIME = 1
PROCESSING_MESSAGE = "processing"
SUCCESS_MESSAGE = "success"
EQUIVALENCE_MESSAGE = "Equivalent."
TOTAL_ROUTERS = 167
TOTAL_TESTCASES = 21
ROUTERS_PER_TESTCASE = {
    '0': 1,
    '1': 1,
    '2': 4,
    '3': 4,
    '4': 4,
    '5': 4,
    '6': 1,
    '7': 1,
    '8': 1,
    '9': 1,
    '10': 1,
    '11': 1,
    '12': 11,
    '13': 10,
    '14': 12,
    '15': 12,
    '16': 13,
    '17': 11,
    '18': 10,
    '19': 12,
    '20': 52,
}

def check_routers_per_testcase_dict():
    routers_in_testcases = 0
    for testcase in ROUTERS_PER_TESTCASE:
        routers_in_testcases += ROUTERS_PER_TESTCASE[testcase]
    if routers_in_testcases != TOTAL_ROUTERS:
        print("WARNING: ROUTERS_PER_TESTCASE dict has the wrong amount of total routers.")


def number_aware_key_generator(entry):
    try:
        key = int(entry)
    except ValueError:
        key = entry
    return key

def can_be_int(entry):
    try:
        key = int(entry)
    except ValueError:
        return False
    return True


def submit(testcases, solution_dir, submission_id_dict):
    for testcase in testcases:
        testcase_dir = os.path.join(solution_dir, testcase)
        if not os.path.isdir(testcase_dir):
            continue

        testcase_dict = collections.OrderedDict()
        submission_id_dict[testcase] = testcase_dict

        routers = os.listdir(testcase_dir)
        routers = [x for x in routers if can_be_int(x)]
        routers.sort(key = number_aware_key_generator)
        for router in routers:
            params = dict()
            params['testcase'] = testcase
            params['router'] = router
            router_file_path = os.path.join(testcase_dir, router)

            while True:
                request = requests.post(
                    url = SUBMISSION_SERVER+SUBMISSION_PATH,
                    params = params,
                    files = {'file': open(router_file_path)}
                )
                if request.status_code == 429:
                    print("Rate limit reached, retrying in 5s")
                    time.sleep(5)
                else:
                    break;

            try:
                submission_id = request.json()['submission_id']
            except json.decoder.JSONDecodeError:
                print(request.content.decode('utf-8'))
                sys.exit(1)
            testcase_dict[router] = submission_id
            print("Testcase {}, router {} has submission id: {}".format(
                testcase, router, submission_id
            ))

def submit_all(solution_dir, submission_id_dict):
## First, submit all the solutions to the server
    testcases = os.listdir(solution_dir)
    testcases = [x for x in testcases if can_be_int(x)]
    testcases.sort(key = number_aware_key_generator)
    submit(testcases, solution_dir, submission_id_dict)

def get_one_result(submission_id):
    waiting_message_written = False
    while True:
        request = requests.get(
            url = SUBMISSION_SERVER+RESULT_PATH,
            params = {'submission_id': submission_id},
        )
        result = request.json()

        if result['status'] == PROCESSING_MESSAGE:
            if not waiting_message_written:
                sys.stdout.write("Server not done, waiting ")
                sys.stdout.flush()
                waiting_message_written = True
            else:
                sys.stdout.write(".")
                sys.stdout.flush()

            time.sleep(PROCESSING_WAIT_TIME)
        else:
            break

    if waiting_message_written:
        sys.stdout.write('\n')

    return result

def get_results(submission_id_dict, result_dict):
    for testcase in submission_id_dict:
        testcase_results = dict()
        result_dict[testcase] = testcase_results
        testcase_submission_ids = submission_id_dict[testcase]
        for router in testcase_submission_ids:
            submission_id = testcase_submission_ids[router]
            result = get_one_result(submission_id)
            if result['status'] == SUCCESS_MESSAGE:
                testcase_results[router] = result
                print("Testcase: {testcase}, Router: {router} is {equivalence}".format(**result))
            else:
                print("Unexpected response from server: {}".format(result))
                sys.exit(1)

# def calculate_score(result_dict):
#     total_score = 0
#     for testcase in result_dict:
#         testcase_score = 0;
#         for router in result_dict[testcase]:
#             if result_dict[testcase][router]['equivalence'] == EQUIVALENCE_MESSAGE:
#                 testcase_score += 1
#         testcase_score /= len(result_dict[testcase])
#         print("Score for testcase {}: {:.2f}".format(testcase, testcase_score))
#         total_score += testcase_score
#     total_score /= len(result_dict)
#     print("Total score: {:.2f}".format(total_score))

def count_correct_routers_in_testcase(testcase):
    correct_routers = 0   
    for router in testcase:
        if testcase[router]['equivalence'] == EQUIVALENCE_MESSAGE:
                correct_routers += 1
    return correct_routers

def count_total_correct_routers(result_dict):
    correct_routers = 0
    for testcase in result_dict:
        correct_routers += count_correct_routers_in_testcase(result_dict[testcase])
    return correct_routers

def count_total_correct_testcases(result_dict):
    correct_testcases = 0
    for testcase in result_dict:
        correct_routers = count_correct_routers_in_testcase(result_dict[testcase])
        correct_testcases += correct_routers == ROUTERS_PER_TESTCASE[testcase]
    return correct_testcases

def print_project_grade(result_dict):
    correct_routers = count_total_correct_routers(result_dict)
    correct_testcases = count_total_correct_testcases(result_dict)
    project_score = correct_testcases/TOTAL_TESTCASES
    project_grade = correct_testcases/TOTAL_TESTCASES * 5 + 1
    print("You correctly generated config files for {} out of {} routers".format(
        correct_routers,
        TOTAL_ROUTERS
    ))
    print("Your solutions are correct for {} out of {} test cases".format(
        correct_testcases,
        TOTAL_TESTCASES
    ))
    print("This corresponds to a score of {:.2}/1".format(project_score))
    print("This corresponds to a project grade of {:.2}/6".format(project_grade))

def write_output_file(result_dict, file_path):
    result = dict()
    correct_router_count = count_total_correct_routers(result_dict)
    total_score_dict = dict(score = correct_router_count, max_score = TOTAL_ROUTERS)
    result['overall-result'] = total_score_dict
    with open(file_path, 'w') as output_file:
        json.dump(result, output_file)

if __name__ == "__main__":

    check_routers_per_testcase_dict()

    parser = parser = argparse.ArgumentParser()
    parser.add_argument('testcases', metavar='testcase', nargs='*', type=str)
    parser.add_argument('-s', '--solution_dir', dest = 'solution_dir', default = 'outputs')
    parser.add_argument('-o', '--output_fall', dest = 'output_file', default = None)
    args = parser.parse_args()

    result_dict = collections.OrderedDict()
    submission_id_dict = collections.OrderedDict()
    if not args.testcases:
        submit_all(args.solution_dir, submission_id_dict)
    else:
        submit(args.testcases, args.solution_dir, submission_id_dict)
    get_results(submission_id_dict, result_dict)
    #calculate_score(result_dict)
    print_project_grade(result_dict)
    if args.output_file:
        write_output_file(result_dict, args.output_file)


