#!/usr/bin/env python3

# Full Name: Omid Farahmand
# Description: Impelementation of a secure, log-based client for photo sharing.
# Each opeartion is protected by a chained HMAC (using a shared secret).
# Photo data is verified using per-photo hashes to detect tampering, while version numbers prevent reordering or replay attacks from a malicious server.

# FOR EDUCATION PURPOSE ONLY. DO NOT SHARE OR DISTRIBUTE WITHOUT PERMISSION

import typing as t
import uuid

from server.reference_server import *
import common.crypto as crypto
import common.types as types
import common.codec as codec
import common.errors as errors
import requests
from ag.common.mock_http import (
    link_client_server,
)  # imported for doctests, unneeded otherwise


class Client:
    """The client for the photo-sharing application.

    A client can query a remote server for the list of a user's photos
    as well as the photos themselves.  A client can also add photos on
    behalf of that user.

    A client retains data required to authenticate a user's device
    both to a remote server and to other devices.  To authenticate to
    the remote server, the client presents a username and auth_secret,
    while to authenticate to other devices, the client tags
    updates with an authenticator over the history of all updates.  To
    verify the authenticity of an update, clients check the
    authenticator using a shared symmetric key.
    """

    # maps response RPC name to the corresponding type
    RESPONSE_MAPPINGS: t.Dict[str, types.RpcObject] = {
        "RegisterResponse": types.RegisterResponse,
        "LoginResponse": types.LoginResponse,
        "UpdatePublicProfileResponse": types.UpdatePublicProfileResponse,
        "GetFriendPublicProfileResponse": types.GetFriendPublicProfileResponse,
        "PutPhotoResponse": types.PutPhotoResponse,
        "GetPhotoResponse": types.GetPhotoResponse,
        "SynchronizeResponse": types.SynchronizeResponse,
    }

    def __init__(
        self,
        username: str,
        remote_url: t.Optional[str] = None,
        user_secret: t.Optional[bytes] = None,
    ) -> None:
        """Initialize a client given a username, a
        remote server's URL, and a user secret.

        If no remote URL is provided, "http://localhost:5000" is assumed.

        If no user secret is provided, this constructor generates a
        new one.
        """
        self._remote_url = remote_url if remote_url else "http://localhost:5000"
        self._client_id = str(uuid.uuid4())

        self._username = username
        self._server_session_token = None

        self._user_secret = crypto.UserSecret(user_secret)

        self._auth_secret = self._user_secret.get_auth_secret()
        self._symmetric_auth = crypto.MessageAuthenticationCode(
            self._user_secret.get_symmetric_key()
        )

        # Local state
        self._photos: t.List[bytes] = []        # list of photos in put_photo order
        self._photo_hashes: t.List[bytes] = []  # Store the hash for each photo_id
        self._last_log_number: int = -1         # We expect version 0 to be the REGISTER
        self._last_chain_hmac = bytes()         # Start the chain HMAC as an empty bytes object
        self._next_photo_id = 0                 # Next photo ID


    def send_rpc(self, request: types.RpcObject) -> types.RpcObject:
        """
        Sends the given RPC object to the server,
        and returns the server's response.

        To do so, does the following:
        - Converts the given RPC object to JSON
        - Sends a POST request to the server's `/rpc` endpoint
            with the RPC JSON as the body
        - Converts the response JSON into the correct RPC object.

        ## DO NOT CHANGE THIS METHOD

        It is overridden for testing, so any changes will be
        overwritten.
        """
        r = requests.post(f"{self._remote_url}/rpc",
                          json=request.as_rpc_dict())
        resp = r.json()
        resp_type = self.RESPONSE_MAPPINGS.get(resp["rpc"], None)
        if resp_type is None:
            raise ValueError(f'Invalid response type "{resp["rpc"]}".')
        resp = resp_type.from_dict(resp["data"])
        return resp
    
    @property
    def username(self) -> str:
        """Get the client's username.

        >>> alice = Client("alice")
        >>> alice.username == "alice"
        True
        """
        return self._username

    @property
    def user_secret(self) -> bytes:
        """Get the client's user secret.

        >>> user_secret = crypto.UserSecret().get_secret()
        >>> alice = Client("alice", user_secret=user_secret)
        >>> alice.user_secret == user_secret
        True
        """
        return self._user_secret.get_secret()

    def register(self) -> None:
        """Register this client's username with the server,
        initializing the user's state on the server.

        If the client is already registered, raise a
        UserAlreadyExistsError.

        Otherwise, save the session token returned by the server for
        use in future requests.

        >>> server = ReferenceServer()
        >>> alice = Client("alice")
        >>> link_client_server(alice, server)

        >>> alice.login()
        Traceback (most recent call last):
                ...
        common.errors.LoginFailedError: failed to log alice in

        >>> alice.register()
        >>> alice.login()
        """
        # Set initial values for registration
        version = 0
        opcode = types.OperationCode.REGISTER
        photo_id = 0 
        photo_hash = bytes()  # No photo hash for the registration.
        prev_hmac = bytes()   # no previous HMAC with start of the chain 
        
        # Compute the HMAC for this log entry
        this_hmac = self._compute_log_hmac(version, opcode.value, photo_id, photo_hash, prev_hmac)

        # Create a LogEntry for registration
        log = LogEntry(
            version=version,
            opcode=opcode.value,
            photo_id=photo_id,
            photo_hash=photo_hash,
            prev_hmac=prev_hmac,
            this_hmac=this_hmac,
        )
        
        # send the register request to the server 
        req = types.RegisterRequest(
            self._client_id, self._username, self._auth_secret, log.encode()
        )
        resp = self.send_rpc(req)

        # handle the server response
        if isinstance(resp, types.RegisterResponse):
            if resp.error is None:
                # Registration success; save session token and update state
                self._server_session_token = resp.token
                self._last_log_number = 0
                self._last_chain_hmac = this_hmac
            elif resp.error == types.Errcode.USER_ALREADY_EXISTS:
                raise errors.UserAlreadyExistsError(self._username)
            else:
                raise Exception(f"{resp.error}")
        else:
            raise Exception("Invalid RPC response")

    def login(self) -> None:
        """Try to login with to the server with the username and
        auth_secret.

        On success, save the new session token returned by the server
        for use in future requests.

        Otherwise, if the username and auth_secret combination is
        incorrect, raise a LoginFailedError.

        >>> server = ReferenceServer()
        >>> alice = Client("alice")
        >>> link_client_server(alice, server)

        >>> alice.login()
        Traceback (most recent call last):
                ...
        common.errors.LoginFailedError: failed to log alice in

        >>> alice.register()
        >>> alice.login()

        >>> not_alice = Client("alice", server)
        >>> link_client_server(not_alice, server)
        >>> not_alice.login()
        Traceback (most recent call last):
                ...
        common.errors.LoginFailedError: failed to log alice in

        See also: Client.register
        """
        req = types.LoginRequest(
            self._client_id, self._username, self._auth_secret)
        resp = self.send_rpc(req)
        if isinstance(resp, types.LoginResponse):
            if resp.error is None:
                self._server_session_token = resp.token
            elif resp.error == types.Errcode.LOGIN_FAILED:
                raise errors.LoginFailedError(self._username)
            else:
                raise Exception(resp)

    def list_photos(self) -> t.List[int]:
        """Fetch a list containing the photo id of each photo stored
        by the user.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> alice.put_photo(photo_blob)
        0
        >>> photo_blob = b'PHOOOTO'
        >>> alice.put_photo(photo_blob)
        1
        >>> photo_blob = b'PHOOT0O'
        >>> alice.put_photo(photo_blob)
        2
        >>> alice.list_photos()
        [0, 1, 2]
        """
        self._synchronize()

        return list(range(self._next_photo_id))

    def get_photo(self, photo_id) -> bytes:
        """Get a photo by ID.

        >>> server = ReferenceServer()
        >>> alice = Client("alice")
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> photo_id = alice.put_photo(photo_blob)
        >>> photo_id
        0
        >>> alice._fetch_photo(photo_id)
        b'PHOTOOO'
        >>> alice._fetch_photo(1)
        Traceback (most recent call last):
                ...
        common.errors.PhotoDoesNotExistError: photo with ID 1 does not exist
        """
        self._synchronize()
        
        if photo_id < 0 or photo_id >= len(self._photos):
            raise errors.PhotoDoesNotExistError(photo_id)
        return self._photos[photo_id]
    
    def _fetch_photo(self, photo_id: int, expected_hash: bytes) -> bytes:
        """Get a photo from the server using the unique PhotoID
            >>> server = ReferenceServer()
            >>> alice = Client("alice", server)
            >>> link_client_server(alice, server)
            >>> alice.register()
            >>> photo_blob = b'PHOTOOO'
            >>> photo_id = alice.put_photo(photo_blob)
            >>> photo_id
            0
            >>> alice._fetch_photo(photo_id)
            b'PHOTOOO'
            >>> alice._fetch_photo(1)
            Traceback (most recent call last):
                    ...
            common.errors.PhotoDoesNotExistError: photo with ID 1 does not exist
            """
        # Send request to get the photo from the server
        req = types.GetPhotoRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            photo_id=photo_id,
        )
        resp = self.send_rpc(req)

        # Handle different server responses
        if isinstance(resp, types.GetPhotoResponse):
            if resp.error == types.Errcode.INVALID_TOKEN:
                raise errors.InvalidTokenError()
            elif resp.error == types.Errcode.PHOTO_DOES_NOT_EXIST:
                raise errors.SynchronizationError(photo_id)
            elif resp.error is not None:
                raise Exception(resp)
        
        # that the retrieved photo matches the expected hash
            actual_hash = crypto.data_hash(resp.photo_blob)
            if actual_hash != expected_hash:
                # tampering detected
                raise errors.SynchronizationError("Photo blob hash mismatch")
            return resp.photo_blob
       

    def _compute_log_hmac(
        self,
        version: int,
        opcode: int,
        photo_id: int,
        photo_hash: bytes,
        prev_hmac: bytes,
    ) -> bytes:
        "Compute HMAC over (version, opcode, photo_id, photo_hash, prev_hmac)."
        # Encode fields into a standardized format
        data_for_mac = [version, opcode, photo_id, photo_hash, prev_hmac]
        encoded = codec.encode(data_for_mac)
        # Generate HMAC with symmetric authentication key
        return self._symmetric_auth.gen_mac(encoded)


    def put_photo(self, photo_blob: bytes):
        """Append a photo_blob to the server's database.

        On success, this returns the unique photo_id associated with
        the newly-added photo.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> alice.put_photo(photo_blob)
        0
        >>> photo_blob = b'PHOOOTO'
        >>> alice.put_photo(photo_blob)
        1
        >>> photo_blob = b'PHOOT0O'
        >>> alice.put_photo(photo_blob)
        2
        """
        self._synchronize() 

        photo_id = self._next_photo_id

        opcode = types.OperationCode.PUT_PHOTO
        version = self._last_log_number + 1

        # Hash the photo for integrity verification
        photo_hash = crypto.data_hash(photo_blob)

        #  compute the HMAC for log entry 
        this_hmac = self._compute_log_hmac(
            version=version,
            opcode=opcode.value,
            photo_id=photo_id,
            photo_hash=photo_hash,
            prev_hmac=self._last_chain_hmac,
        )

        # create the log entry for uploaded photo
        log = LogEntry(version, opcode.value, photo_id, photo_hash, self._last_chain_hmac, this_hmac)

        
        # Send the put_photo RPC to the server
        req = types.PutPhotoRequest(
            self._client_id,
            self._username,
            self._server_session_token,
            log.encode(),
            photo_blob,
            photo_id,
        )
        resp = self.send_rpc(req)
        # Handle errors from the server
        if isinstance(resp, types.PutPhotoResponse):
            if resp.error == types.Errcode.INVALID_TOKEN:
                raise errors.InvalidTokenError()
            elif resp.error is not None:
                raise Exception(resp)
       

        # If server accepted, locally finalize the addition
        self._record_new_photo(log, photo_blob)
        return photo_id

    def _record_new_photo(self, log_entry: "LogEntry", photo_blob: bytes):
        """
        Locally record a new photo.
        """
          # Update log tracking variables
        self._last_log_number = log_entry.version
        self._last_chain_hmac = log_entry.this_hmac

        if log_entry.opcode == types.OperationCode.PUT_PHOTO.value:
             # Store the photo and its hash, update the photo counter
            self._photos.append(photo_blob)
            self._photo_hashes.append(log_entry.photo_hash)
            self._next_photo_id += 1
        elif log_entry.opcode == types.OperationCode.REGISTER.value:
             # No local action needed for register
            pass

    def _synchronize(self):
        """Synchronize the client's state against the server.

        On failure, this raises a SynchronizationError.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> user_secret = alice.user_secret
        >>> alicebis = Client("alice", server, user_secret)
        >>> link_client_server(alicebis, server)
        >>> alicebis.login()
        >>> alicebis._synchronize()
        >>> alice.login()
        >>> photo_blob = b'PHOTOOO'
        >>> alice._synchronize()
        >>> alice.put_photo(photo_blob)
        0
        >>> photo_blob = b'PHOOOTO'
        >>> alice.put_photo(photo_blob)
        1
        >>> alicebis.login()
        >>> photo_blob = b'PHOOT0O'
        >>> alicebis._synchronize()
        >>> photo_blob = b'PHOOT0O'
        >>> alicebis.put_photo(photo_blob)
        2
        """
        # request new log entries from the server 
        req = types.SynchronizeRequest(
            self._client_id,
            self._username,
            self._server_session_token,
            # request entries starting from next expected version
            self._last_log_number+1,
        )
        
        resp = self.send_rpc(req)
        #server response error handle
        if isinstance(resp, types.SynchronizeResponse):
            if resp.error == types.Errcode.INVALID_TOKEN:
                raise errors.InvalidTokenError()
            elif resp.error == types.Errcode.VERSION_TOO_HIGH:
                raise errors.SynchronizationError(errors.VersionTooHighError())
            elif resp.error is not None:
                raise Exception(resp)

            # Process each new log entry:
            for encoded_log in resp.encoded_log_entries:
                # Decode
                try:
                    new_entry = LogEntry.decode(encoded_log)
                except errors.MalformedEncodingError as e:
                    raise errors.SynchronizationError(e)

                # log version to be seuqential
                if new_entry.version != self._last_log_number + 1:
                    raise errors.SynchronizationError(
                        f"Expected version {self._last_log_number+1}, got {new_entry.version}"
                    )

                #  validate previous HMAC matches our last known chain
                if new_entry.prev_hmac != self._last_chain_hmac:
                    raise errors.SynchronizationError("HMAC mismatch")

                # verfiy HMAC and check
                expected_hmac = self._compute_log_hmac(
                    version=new_entry.version,
                    opcode=new_entry.opcode,
                    photo_id=new_entry.photo_id,
                    photo_hash=new_entry.photo_hash,
                    prev_hmac=new_entry.prev_hmac,
                )
                if expected_hmac != new_entry.this_hmac:
                    raise errors.SynchronizationError("this_hmac verification failed")

                # handle the put_photo and register log entries
                if new_entry.opcode == types.OperationCode.PUT_PHOTO.value:
                    fetched_blob = self._fetch_photo(new_entry.photo_id, new_entry.photo_hash)
                    # accept the new photo
                    self._record_new_photo(new_entry, fetched_blob)
                elif new_entry.opcode == types.OperationCode.REGISTER.value:
                    # accept the registration entry
                    self._record_new_photo(new_entry, bytes())
                else:
                    raise errors.SynchronizationError(resp)

       
class LogEntry:
  
    def __init__(
            # local varaibles
        self,
        version: int,
        opcode: int,
        photo_id: int,
        photo_hash: bytes,
        prev_hmac: bytes,
        this_hmac: bytes,
    ) -> None:
        # initializing the log entries with its required fields
        self.version = version
        self.opcode = opcode
        self.photo_id = photo_id
        self.photo_hash = photo_hash
        self.prev_hmac = prev_hmac
        self.this_hmac = this_hmac

    def encode(self) -> bytes:
        """Encode the log entry in a standardized format."""
        # Put everything in a list to be encoded
        obj = [
            self.version,
            self.opcode,
            self.photo_id,
            self.photo_hash,
            self.prev_hmac,
            self.this_hmac,
        ]
        return codec.encode(obj)

    @classmethod
    def decode(cls, data: bytes) -> "LogEntry":
        """Decode a bytes object into LogEntry, ensuring data integrity"""
        try:
            decoded = codec.decode(data)
            # ensure the correct structure
            if not isinstance(decoded, list) or len(decoded) != 6:
                raise errors.MalformedEncodingError("LogEntry decode mismatch")
            version, opcode, photo_id, photo_hash, prev_hmac, this_hmac = decoded

            # check type validation
            if not (isinstance(version, int) and isinstance(opcode, int) and isinstance(photo_id, int)):
                raise errors.MalformedEncodingError("invalid data types")
            if not (isinstance(photo_hash, bytes) and isinstance(prev_hmac, bytes) and isinstance(this_hmac, bytes)):
                raise errors.MalformedEncodingError("invalid hash types")

            return cls(version, opcode, photo_id, photo_hash, prev_hmac, this_hmac)
        except Exception as e:
            if isinstance(e, errors.MalformedEncodingError):
                raise # raise an errors
            raise errors.MalformedEncodingError(str(e)) #convert errors
