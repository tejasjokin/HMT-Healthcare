import inspect
from typing import NamedTuple

Suspicion = NamedTuple("SuspicionCode", [("code", int), ("reason", str)])


class Suspicions:
    PPR_TO_PRIMARY = \
        Suspicion(1, "PRE-PREPARE being sent to primary")
    DUPLICATE_PPR_SENT = \
        Suspicion(2,
                  "PRE-PREPARE being sent twice with the same view no and "
                  "sequence no")
    DUPLICATE_PR_SENT = \
        Suspicion(3, "PREPARE request already received")
    UNKNOWN_PR_SENT = \
        Suspicion(4, "PREPARE request for unknown PRE-PREPARE request")
    PR_DIGEST_WRONG = \
        Suspicion(5, "PREPARE request digest is incorrect")
    UNKNOWN_CM_SENT = \
        Suspicion(6, "Commit requests when no prepares received")
    CM_DIGEST_WRONG = \
        Suspicion(7, "Commit requests has incorrect digest")
    DUPLICATE_CM_SENT = \
        Suspicion(8, "COMMIT message has already received")
    PPR_FRM_NON_PRIMARY = \
        Suspicion(9, "Pre-Prepare received from non primary")
    PR_FRM_PRIMARY = \
        Suspicion(10, "Prepare received from primary")
    PPR_DIGEST_WRONG = \
        Suspicion(11, "Pre-Prepare message has incorrect digest")
    DUPLICATE_INST_CHNG = \
        Suspicion(12, "Duplicate instance change message received")
    FREQUENT_INST_CHNG = \
        Suspicion(13, "Too many instance change messages received")
    DUPLICATE_NOM_SENT = \
        Suspicion(14, "NOMINATION request already received")
    DUPLICATE_PRI_SENT = \
        Suspicion(15, "PRIMARY request already received")
    DUPLICATE_REL_SENT = \
        Suspicion(16, "REELECTION request already received")
    WRONG_PPSEQ_NO = \
        Suspicion(17, "Wrong PRE-PREPARE seq number")
    PPR_TIME_WRONG = \
        Suspicion(18, "PRE-PREPARE time not acceptable")
    CM_TIME_WRONG = \
        Suspicion(19, "COMMIT time does not match with PRE-PREPARE")
    PPR_REJECT_WRONG = \
        Suspicion(20, "Pre-Prepare message has incorrect reject")
    PPR_STATE_WRONG = \
        Suspicion(21, "Pre-Prepare message has incorrect state trie root")
    PPR_TXN_WRONG = Suspicion(
        22, "Pre-Prepare message has incorrect transaction tree root")
    PR_STATE_WRONG = \
        Suspicion(23, "Prepare message has incorrect state trie root")
    PR_TXN_WRONG = \
        Suspicion(24, "Prepare message has incorrect transaction tree root")
    PRIMARY_DEGRADED = Suspicion(25, 'Primary of master protocol instance '
                                     'degraded the performance')
    PRIMARY_DISCONNECTED = Suspicion(26, 'Primary of master protocol instance '
                                         'disconnected')
    PRIMARY_ABOUT_TO_BE_DISCONNECTED = Suspicion(
        27, 'Primary of master '
            'protocol instance '
            'about to be disconnected')
    INSTANCE_CHANGE_TIMEOUT = Suspicion(28, 'View change could not complete '
                                            'in time')
    PPR_BLS_MULTISIG_WRONG = \
        Suspicion(29, "Pre-Prepare message has invalid BLS multi-signature")
    CM_BLS_SIG_WRONG = \
        Suspicion(31, "Commit message has invalid BLS signature")
    PR_BLS_SIG_WRONG = \
        Suspicion(32, "Prepare message has invalid BLS signature")

    PPR_PLUGIN_EXCEPTION = Suspicion(35, "Pre-Prepare message has error in plugin field")
    PR_PLUGIN_EXCEPTION = Suspicion(36, "Prepare message has error in plugin field")
    PPR_SUB_SEQ_NO_WRONG = Suspicion(37, "Pre-Prepare message has wrong sub_seq_no")
    PPR_NOT_FINAL = Suspicion(38, "Pre-Prepare message is not final")
    BACKUP_PRIMARY_DISCONNECTED = Suspicion(39, "Primary on backup instance was disconnected.")
    BACKUP_PRIMARY_DEGRADED = Suspicion(40, "Backup instance was performance degraded.")
    PPR_POOL_STATE_ROOT_HASH_WRONG = Suspicion(41, "Pre-Prepare message has "
                                                   "incorrect pool state root hash")
    PPR_WITH_ORDERED_REQUEST = Suspicion(42, "Pre-Prepare message has already ordered requests")
    STATE_SIGS_ARE_NOT_UPDATED = Suspicion(43, "State signatures are not updated for too long")
    PPR_AUDIT_TXN_ROOT_HASH_WRONG = Suspicion(44, "Pre-Prepare message has "
                                                  "incorrect audit ledger transaction root hash")
    PR_AUDIT_TXN_ROOT_HASH_WRONG = Suspicion(45, "Prepare message has "
                                                 "incorrect audit ledger transaction root hash")

    NODE_COUNT_CHANGED = Suspicion(46, "Node's count changed")
    NEW_VIEW_INVALID_CHECKPOINTS = Suspicion(47, "New View's Primary sent NewView with invalid checkpoints")
    NEW_VIEW_INVALID_BATCHES = Suspicion(48, "New View's Primary sent NewView with invalid batches")
    INCORRECT_NEW_PRIMARY = Suspicion(49, "In view change selected master primary is the same with the "
                                          "current master primary")
    PPR_WITH_WRONG_PRIMARIES = Suspicion(50, "Pre-Prepare message has wrong list of primaries")
    PRIMARY_DEMOTED = Suspicion(51, "Master Primary is demoted")
    DEBUG_FORCE_VIEW_CHANGE = Suspicion(777, "DEBUG Need to do forced view change")

    @classmethod
    def get_list(cls):
        return [member for nm, member in inspect.getmembers(cls) if isinstance(
            member, Suspicion)]

    @classmethod
    def get_by_code(cls, code):
        for s in Suspicions.get_list():
            if code == s.code:
                return s