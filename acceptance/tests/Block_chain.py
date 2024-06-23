import numpy as np
import time
import warnings
warnings.filterwarnings("ignore")
import acceptance.tests.test_ledger
def saving_data(Certificate):
    acceptance.tests.test_ledger.chain(Certificate,4)

    Certificate_=Certificate
    return Certificate_
def saving_data1(Certificate):
    acceptance.tests.test_ledger.chain(Certificate,4)

    Certificate_=Certificate
    return Certificate_
def acc_request(user):
    return print("user request accepted")


