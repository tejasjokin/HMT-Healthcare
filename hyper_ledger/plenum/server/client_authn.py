"""
Clients are authenticated with a digital signature.
"""
from abc import abstractmethod
from typing import Dict, Optional

import base58
from hyper_ledger.common.serialization import serialize_msg_for_signing
from hyper_ledger.plenum.common.constants import VERKEY, ROLE, NYM
from hyper_ledger.plenum.common.exceptions import EmptySignature, MissingSignature, EmptyIdentifier, \
    MissingIdentifier, CouldNotAuthenticate, InvalidSignatureFormat, InsufficientSignatures, \
    InsufficientCorrectSignatures
from hyper_ledger.plenum.common.types import f
from hyper_ledger.plenum.common.verifier import DidVerifier, Verifier
from hyper_ledger.stp_core.common.log import getlogger

logger = getlogger()


class ClientAuthNr:
    """
    Interface for client authenticators.
    """

    @abstractmethod
    def authenticate(self,
                     msg: Dict,
                     identifier: Optional[str] = None,
                     signature: Optional[str] = None,
                     threshold: Optional[int] = None,
                     key: Optional[str] = None) -> str:
        """
        Authenticate the client's message with the signature provided.
        :param identifier: some unique identifier; if None, then try to use
        msg['identifier'] as identifier
        :param signature: a utf-8 and base58 encoded signature
        :param msg: the message to authenticate
        :param threshold: The number of successful signature verification
        :param key: The key of request for storing in internal maps
        required. By default all signatures are required to be verified.
        :return: the identifier; an exception of type SigningException is
            raised if the signature is not valid
        """

    @abstractmethod
    def authenticate_multi(self, msg: Dict, signatures: Dict[str, str],
                           threshold: Optional[int] = None):
        """
        :param msg:
        :param signatures: A mapping from identifiers to signatures.
        :param threshold: The number of successful signature verification
        required. By default all signatures are required to be verified.
        :return: returns the identifiers whose signature was matched and
        correct; a SigningException is raised if threshold was not met
        """

    @abstractmethod
    def addIdr(self, identifier, verkey, role=None):
        """
        Adding an identifier should be an auditable and authenticated action.
        Robust implementations of ClientAuthNr would authenticate this
        operation.
        :param identifier: an identifier that directly or indirectly identifies
            a client
        :param verkey: the public key used to verify a signature
        :return: None
        """

    @abstractmethod
    def getVerkey(self, identifier):
        """
        Get the verification key for a client based on the client's identifier
        :param identifier: client's identifier
        :return: the verification key
        """


class NaclAuthNr(ClientAuthNr):

    def authenticate_multi(self, msg: Dict, signatures: Dict[str, str],
                           threshold: Optional[int] = None, verifier: Verifier = DidVerifier):

        num_sigs = len(signatures)
        if threshold is not None:
            if num_sigs < threshold:
                raise InsufficientSignatures(num_sigs, threshold)
        else:
            threshold = num_sigs

        correct_sigs_from = []
        incorrect_signatures = {}
        for idr, sig in signatures.items():
            try:
                sig_decoded = base58.b58decode(sig)
            except Exception as ex:
                raise InvalidSignatureFormat from ex

            ser = self.serializeForSig(msg, identifier=idr)

            verkey = self.getVerkey(idr, msg)
            if verkey is None:
                raise CouldNotAuthenticate(idr)

            vr = verifier(verkey, identifier=idr)
            if vr.verify(sig_decoded, ser):
                correct_sigs_from.append(idr)
                if len(correct_sigs_from) == threshold:
                    break
            else:
                incorrect_signatures[idr] = sig
        else:
            raise InsufficientCorrectSignatures(threshold, len(correct_sigs_from), incorrect_signatures)

        return correct_sigs_from

    @abstractmethod
    def addIdr(self, identifier, verkey, role=None):
        pass

    @abstractmethod
    def getVerkey(self, ident, request):
        pass

    def serializeForSig(self, msg, identifier=None, topLevelKeysToIgnore=None):
        return serialize_msg_for_signing(
            msg, topLevelKeysToIgnore=topLevelKeysToIgnore)


class SimpleAuthNr(NaclAuthNr):
    """
    Simple client authenticator. Should be replaced with a more robust and
    secure system.
    """

    def __init__(self, state=None):
        # key: some identifier, value: verification key
        self.clients = {}  # type: Dict[str, Dict]
        self.state = state
        self.specific_verkey_validation = {NYM: self.nym_specific_auth}

    def addIdr(self, identifier, verkey, role=None):
        if identifier in self.clients:
            # raise RuntimeError("client already added")
            logger.debug("client already added")
        self.clients[identifier] = {
            VERKEY: verkey,
            ROLE: role
        }



    def authenticate(self,
                     msg: Dict,
                     identifier: Optional[str] = None,
                     signature: Optional[str] = None,
                     threshold: Optional[int] = None):
        signatures = {identifier: signature}
        return self.authenticate_multi(msg, signatures=signatures, threshold=threshold)




class CoreAuthMixin:
    # TODO: This should know a list of valid fields rather than excluding
    # hardcoded fields
    excluded_from_signing = {f.SIG.nm, f.SIGS.nm, f.FEES.nm}

    def __init__(self, write_types, query_types, action_types) -> None:
        self._write_types = set(write_types)
        self._query_types = set(query_types)
        self._action_types = set(action_types)

    def is_query(self, typ):
        return typ in self._query_types

    def is_write(self, typ):
        return typ in self._write_types

    def is_action(self, typ):
        return typ in self._action_types

    @staticmethod
    def _extract_signature(msg):
        if f.SIG.nm not in msg:
            raise MissingSignature
        if not msg[f.SIG.nm]:
            raise EmptySignature
        return msg[f.SIG.nm]

    @staticmethod
    def _extract_identifier(msg):
        if f.IDENTIFIER.nm not in msg:
            raise MissingIdentifier
        if not msg[f.IDENTIFIER.nm]:
            raise EmptyIdentifier
        return msg[f.IDENTIFIER.nm]

    def authenticate(self, req_data, identifier: Optional[str] = None,
                     signature: Optional[str] = None, threshold: Optional[int] = None,
                     verifier: Verifier = DidVerifier):
        """
        Prepares the data to be serialised for signing and then verifies the
        signature
        :param req_data:
        :param identifier:
        :param signature:
        :param verifier:
        :return:
        """
        to_serialize = {k: v for k, v in req_data.items()
                        if k not in self.excluded_from_signing}
        if req_data.get(f.SIG.nm) is None and \
                req_data.get(f.SIGS.nm) is None and \
                signature is None:
            raise MissingSignature
        if req_data.get(f.IDENTIFIER.nm) and (req_data.get(f.SIG.nm) or
                                              signature):
            try:
                # if not identifier:
                identifier = identifier or self._extract_identifier(req_data)

                # if not signature:
                signature = signature or self._extract_signature(req_data)

                signatures = {identifier: signature}
            except Exception as ex:
                if ex in (MissingSignature, EmptySignature, MissingIdentifier,
                          EmptyIdentifier):
                    ex = ex(req_data.get(f.IDENTIFIER.nm), req_data.get(f.SIG.nm))
                raise ex
        else:
            signatures = req_data.get(f.SIGS.nm, None)
        return self.authenticate_multi(to_serialize, signatures=signatures,
                                       threshold=threshold, verifier=verifier)

    def serializeForSig(self, msg, identifier=None, topLevelKeysToIgnore=None):
        return serialize_msg_for_signing(
            msg, topLevelKeysToIgnore=topLevelKeysToIgnore)


class CoreAuthNr(CoreAuthMixin, SimpleAuthNr):
    def __init__(self, write_types, query_types, action_types, state=None):
        SimpleAuthNr.__init__(self, state)
        CoreAuthMixin.__init__(self, write_types, query_types, action_types)