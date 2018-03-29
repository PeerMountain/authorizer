class Parameters(object):
    TOLERABLE_TIME_DIFFERENCE_IN_SECONDS = 420

class MessageTypes(object):
    INVITE = 0
    REGISTRATION = 1
    ASSERTION = 2
    ATTESTATION = 3
    SERVICE = 4
    DELEGATION = 5

class BodyTypes(object):
    'Body Types enum container class'

    class System(object):
        'System message Body Types'
        '''Audit checkpoint records'''
        CHECKPOINT = 0

    class Registration(object):
        'Registration Message Body Types'

        '''Invite new participant'''
        INVITATION = 0
        '''Register persona'''
        REGISTRATION = 1
        '''Delegate existing persona'''
        DELEGATION = 2
        '''Key Recovery Vault'''
        BACKUP = 3
        '''Key Recovery Request'''
        RECOVER = 4

    class Assertion(object):
        'Assertion Message Body Types'

        '''Provide attestation to subject'''
        DIRECT_ATTESTATION = 0
        '''Request source object review'''
        VERIFICATION_REQUEST = 1

    class Attestation(object):
        'Attestation Message Body Types'

        '''Offer service'''
        SERVICE_OFFERING = 0
        '''Provide dossier for service'''
        SERVICE_REQUEST = 1
        '''Request ad-hoc dossier addition'''
        AMENDMENT_REQUEST = 2

    class Service(object):
        'Service Message Body Types'

        '''Delegation'''
        DELEGATION = 0
        '''Validation'''
        VALIDATION = 1

PUBLIC_AES_KEY = b'Peer Mountain'
