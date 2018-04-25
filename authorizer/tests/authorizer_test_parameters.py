import pytest
import base64
import umsgpack
import msgpack  # still used in some edge cases

from authorizer import identity
from libs.AES import AES
from libs.RSA import RSA

EXPECTED_HASHES = [ ("qwertyuiop", b'\x9a\x90\x04\x03\xac1;\xa2z\x1b\xc8\x1f\t2e+\x80 \xda\xc9,#M\x98\xfa\x0b\x06\xbf\x00@\xec\xfd'),
    ("asdfghjkl", b'\\\x80V]\xb6\xf2\x9d\xa0\xb0\x1a\xa1%"\xc3{2\xf1!\xcb\xe4z\x86\x1e\xf7\xf0\x06\xcb"\x92-\xff\xa1'),
    ("zxcvbnm", b'\x1d\xf1\x85@\x15\xe3\x1c\xa2\x86\xd0\x154^\xaf\xf2\x9al`s\xf7\t\x84\xa3\xa7F\x82=L\xac\x16\xb0u'),
    pytest.param("qwertyuiop", b"this isn't the hash at all", marks=pytest.mark.xfail(strict=True)),
    pytest.param("qwertyuiop", b"", marks=pytest.mark.xfail(strict=True)),
    pytest.param("1234444", b"", marks=pytest.mark.xfail(strict=True)),
]

TELEFERIC_SIGNATURE = (
    b'\x82\xa9signature\xda\x02\xacJ8/N0tlXAmZIBrfRZxSfkjXdIr0gM6EuyZU8OeB8'
    b'sB689QgikKX1g7mpSGMqJRgafO5q/ffhFlLAwZkMlw25YAC+4+N3eY3FH8h/zDgSSOdpgYGY/sCbPpKD'
    b'uLekMR4a3M+xqeH/kBheGMM13pIt9DVOaiiJKuEeLR9JY4do/Jl6cUNUvVW9C0qur4pPbie8bCpg2biS'
    b'Za3/X2N0R9+GOSq1KOy3RF4rHZdEJDMw9JCBdgD2GfVDOl2K+jkeJAHafa+O5w64SoMuwDweV3LlYgRN'
    b'7ZNxrTE6q7wLPKFYbSXE7lifL/3yA5t1RWuFDZBiLJB0+lEa5alfKunyObcO827upLaipFcuXp7SVg7M'
    b'w9Ow+x4SJw/MaQN6lS4sZcSYFinbqDqAiEYXKDUzmibw4Ee39OXo74tjMwf++cN+AN3FPni2XQJSl+ql'
    b'50AhUsJZLfW0w1JmpQbI1CNhrr42fdecP/Jz7awc32hE96GVToy0hwr3pnvKcoQYtTGG9cjxVqS6PodY'
    b'0qtyBd97YU89ngfGGyiSnNaap8w0nFtKK9s0GXPFFKdz9M1WDFVhiyhZL5t/jfQ8nlnSlrMpbitqgGxD'
    b'XHCM+GHfN3lLa5rTkqVkCBM5iNjTRZifpoGOqjF3OmxlX9RigUD3vkYQDV9t/vxKRPSs7cNx19dx/0r5'
    b'Gxc=\xa9timestamp\xb21520445993.9620507'
)

SIGNATURES = [
    (base64.b64encode(b'\x82\xa9signature\xda\x02\xacKWi2HPm3cS1t6GzHNaEe1sAcvC/pQ2lWafam6thanBRXk/jP5iSgvPDcGZmxx55PSqMcF+DT2vJKIdNVOT5aDuHFpCAHVfOQY15X66vnG/GIlXSnsNgKtcdGomyrLEhlywDaC/IRQwvwA3p1sz5R/7JOuq/9H1aTAmfm9GjTL7OsQt6kQejgNnBbUW0OAvqRIFaBcdfDwcQtGQxlWo/9XNoEYyPz4JqFDBTdbxC0Ysbj9STaJq748Y2eNE0OIwShNcNrKVYdtmpDsVMvm+Ciiqddc9eb6eOop6zhEJ4RaJzwa4ybF/nZ7OO1Azqomjr9hcUTodutVSVAJMEKTJZb3Di+l9yd8XUZsjmH7csphOI9FjS+ibqFwHhBH/Bjlq7jXGXUaa36/ZPPd4jUrIWgFWs+zQi0NT9ohMzo0Ag0k963dCZ/sDNG/Wr5t2SYKPsx+cA/m+hMa5F9GXVM2dDU+xVEVkr2N31EUeXcel4MVYvuaTpwvTEGoZLT00X+RsTX3BzjI3xBOQ67MA1CnlIsJK5W/mlj0X39dFo7HWN+ot2F4dHyaHuHiSCDzfWfkFHXH+zgSG4dNFYQ8cdg78J6qsIViHeMzmAFm3IGNOgXwWPdDEBch+2rMiDzwA+PRi4X/ziV7Vx0+8y6G8W7kSVjke2TKZk9Pa7QzPqqCTnY4WU=\xa9timestamp\xda\x03\xccgqlzaWduYXR1cmXaAqxKOC9OMHRsWEFtWklCcmZSWnhTZmtqWGRJcjBnTTZFdXlaVThPZUI4c0I2ODlRZ2lrS1gxZzdtcFNHTXFKUmdhZk81cS9mZmhGbExBd1prTWx3MjVZQUMrNCtOM2VZM0ZIOGgvekRnU1NPZHBnWUdZL3NDYlBwS0R1TGVrTVI0YTNNK3hxZUgva0JoZUdNTTEzcEl0OURWT2FpaUpLdUVlTFI5Slk0ZG8vSmw2Y1VOVXZWVzlDMHF1cjRwUGJpZThiQ3BnMmJpU1phMy9YMk4wUjkrR09TcTFLT3kzUkY0ckhaZEVKRE13OUpDQmRnRDJHZlZET2wySytqa2VKQUhhZmErTzV3NjRTb011d0R3ZVYzTGxZZ1JON1pOeHJURTZxN3dMUEtGWWJTWEU3bGlmTC8zeUE1dDFSV3VGRFpCaUxKQjArbEVhNWFsZkt1bnlPYmNPODI3dXBMYWlwRmN1WHA3U1ZnN013OU93K3g0U0p3L01hUU42bFM0c1pjU1lGaW5icURxQWlFWVhLRFV6bWlidzRFZTM5T1hvNzR0ak13ZisrY04rQU4zRlBuaTJYUUpTbCtxbDUwQWhVc0paTGZXMHcxSm1wUWJJMUNOaHJyNDJmZGVjUC9Kejdhd2MzMmhFOTZHVlRveTBod3IzcG52S2NvUVl0VEdHOWNqeFZxUzZQb2RZMHF0eUJkOTdZVTg5bmdmR0d5aVNuTmFhcDh3MG5GdEtLOXMwR1hQRkZLZHo5TTFXREZWaGl5aFpMNXQvamZROG5sblNsck1wYml0cWdHeERYSENNK0dIZk4zbExhNXJUa3FWa0NCTTVpTmpUUlppZnBvR09xakYzT214bFg5UmlnVUQzdmtZUURWOXQvdnhLUlBTczdjTngxOWR4LzByNUd4Yz2pdGltZXN0YW1wsjE1MjA0NDU5OTMuOTYyMDUwNw=='), 'asd'),
    (base64.b64encode(b'\x82\xa9signature\xda\x02\xacGNk49I43+Vnfnh6y67PozBfvznq2jlW5uI14EAVKvY15NwCMmZj9N05jdIfG5sAXrrc8s/oQ+xu+FIa87vO5CF7vWznH3hy45u7yyEbIQA89te1cCJ5MSn/v+a0pDKSQcGWZ7ksd9KjtIqYdzvXNjCFdlZKM4F8lMKD4dUHpFmUjdYRs/vYsXBGrRZKT9zGp0AfJjLxcb2QKQvND2Y31hgzep0gtN9ROOyKiERyGQCScSeEzsSbgTjuO0ZcLQbBqcHjDvypM4u5h5TQnyDjYrqnzsvItMzS18QrtTH9YOWCNBKYCzgCDaPZr+0O+KOwCvSx3OEepLcbmovo2W9Z4QBFNvWwVxf5FS9gulSeKASgEQ37APqkUZ+WB2pjLr32yZ6duUo8EsWprBkSu3usSBkyRxN4JgV/O2x+JgARPTZR86dQWIeWSMw/fpdvqGzcgJy3M8wjVfzRGKM/P5a+Rcgg+1+p05hrthIT6ejQgMD9vd62ZAEHkdoqhjzY6rnsJeKKV9noSECTAWh8oJPCLz+issx2niE+4HUVIAr8t510roJYkHZqu7YWFXjGLj+SYUelbd6qTxuHtQK0u39bTJUdQtQm20QCgtFkx2Vu6kZmCUY/n07x3Ef4hb5CWLmeTpBh0Bqp/YUf6DBDlwRLyFMtuiu9xcK0zjnFFVDSNuiI=\xa9timestamp\xda\x03\xccgqlzaWduYXR1cmXaAqxKOC9OMHRsWEFtWklCcmZSWnhTZmtqWGRJcjBnTTZFdXlaVThPZUI4c0I2ODlRZ2lrS1gxZzdtcFNHTXFKUmdhZk81cS9mZmhGbExBd1prTWx3MjVZQUMrNCtOM2VZM0ZIOGgvekRnU1NPZHBnWUdZL3NDYlBwS0R1TGVrTVI0YTNNK3hxZUgva0JoZUdNTTEzcEl0OURWT2FpaUpLdUVlTFI5Slk0ZG8vSmw2Y1VOVXZWVzlDMHF1cjRwUGJpZThiQ3BnMmJpU1phMy9YMk4wUjkrR09TcTFLT3kzUkY0ckhaZEVKRE13OUpDQmRnRDJHZlZET2wySytqa2VKQUhhZmErTzV3NjRTb011d0R3ZVYzTGxZZ1JON1pOeHJURTZxN3dMUEtGWWJTWEU3bGlmTC8zeUE1dDFSV3VGRFpCaUxKQjArbEVhNWFsZkt1bnlPYmNPODI3dXBMYWlwRmN1WHA3U1ZnN013OU93K3g0U0p3L01hUU42bFM0c1pjU1lGaW5icURxQWlFWVhLRFV6bWlidzRFZTM5T1hvNzR0ak13ZisrY04rQU4zRlBuaTJYUUpTbCtxbDUwQWhVc0paTGZXMHcxSm1wUWJJMUNOaHJyNDJmZGVjUC9Kejdhd2MzMmhFOTZHVlRveTBod3IzcG52S2NvUVl0VEdHOWNqeFZxUzZQb2RZMHF0eUJkOTdZVTg5bmdmR0d5aVNuTmFhcDh3MG5GdEtLOXMwR1hQRkZLZHo5TTFXREZWaGl5aFpMNXQvamZROG5sblNsck1wYml0cWdHeERYSENNK0dIZk4zbExhNXJUa3FWa0NCTTVpTmpUUlppZnBvR09xakYzT214bFg5UmlnVUQzdmtZUURWOXQvdnhLUlBTczdjTngxOWR4LzByNUd4Yz2pdGltZXN0YW1wsjE1MjA0NDU5OTMuOTYyMDUwNw=='), 'dsa'),
    pytest.param(base64.b64encode(b'\x82\xa9signature\xda\x02\xacGNk49I43+Vnfnh6y67PozBfvznq2jlW5uI14EAVKvY15NwCMmZj9N05jdIfG5sAXrrc8s/oQ+xu+FIa87vO5CF7vWznH3hy45u7yyEbIQA89te1cCJ5MSn/v+a0pDKSQcGWZ7ksd9KjtIqYdzvXNjCFdlZKM4F8lMKD4dUHpFmUjdYRs/vYsXBGrRZKT9zGp0AfJjLxcb2QKQvND2Y31hgzep0gtN9ROOyKiERyGQCScSeEzsSbgTjuO0ZcLQbBqcHjDvypM4u5h5TQnyDjYrqnzsvItMzS18QrtTH9YOWCNBKYCzgCDaPZr+0O+KOwCvSx3OEepLcbmovo2W9Z4QBFNvWwVxf5FS9gulSeKASgEQ37APqkUZ+WB2pjLr32yZ6duUo8EsWprBkSu3usSBkyRxN4JgV/O2x+JgARPTZR86dQWIeWSMw/fpdvqGzcgJy3M8wjVfzRGKM/P5a+Rcgg+1+p05hrthIT6ejQgMD9vd62ZAEHkdoqhjzY6rnsJeKKV9noSECTAWh8oJPCLz+issx2niE+4HUVIAr8t510roJYkHZqu7YWFXjGLj+SYUelbd6qTxuHtQK0u39bTJUdQtQm20QCgtFkx2Vu6kZmCUY/n07x3Ef4hb5CWLmeTpBh0Bqp/YUf6DBDlwRLyFMtuiu9xcK0zjnFFVDSNuiI=\xa9timestamp\xda\x03\xccgqlzaWduYXR1cmXaAqxKOC9OMHRsWEFtWklCcmZSWnhTZmtqWGRJcjBnTTZFdXlaVThPZUI4c0I2ODlRZ2lrS1gxZzdtcFNHTXFKUmdhZk81cS9mZmhGbExBd1prTWx3MjVZQUMrNCtOM2VZM0ZIOGgvekRnU1NPZHBnWUdZL3NDYlBwS0R1TGVrTVI0YTNNK3hxZUgva0JoZUdNTTEzcEl0OURWT2FpaUpLdUVlTFI5Slk0ZG8vSmw2Y1VOVXZWVzlDMHF1cjRwUGJpZThiQ3BnMmJpU1phMy9YMk4wUjkrR09TcTFLT3kzUkY0ckhaZEVKRE13OUpDQmRnRDJHZlZET2wySytqa2VKQUhhZmErTzV3NjRTb011d0R3ZVYzTGxZZ1JON1pOeHJURTZxN3dMUEtGWWJTWEU3bGlmTC8zeUE1dDFSV3VGRFpCaUxKQjArbEVhNWFsZkt1bnlPYmNPODI3dXBMYWlwRmN1WHA3U1ZnN013OU93K3g0U0p3L01hUU42bFM0c1pjU1lGaW5icURxQWlFWVhLRFV6bWlidzRFZTM5T1hvNzR0ak13ZisrY04rQU4zRlBuaTJYUUpTbCtxbDUwQWhVc0paTGZXMHcxSm1wUWJJMUNOaHJyNDJmZGVjUC9Kejdhd2MzMmhFOTZHVlRveTBod3IzcG52S2NvUVl0VEdHOWNqeFZxUzZQb2RZMHF0eUJkOTdZVTg5bmdmR0d5aVNuTmFhcDh3MG5GdEtLOXMwR1hQRkZLZHo5TTFXREZWaGl5aFpMNXQvamZROG5sblNsck1wYml0cWdHeERYSENNK0dIZk4zbExhNXJUa3FWa0NCTTVpTmpUUlppZnBvR09xakYzT214bFg5UmlnVUQzdmtZUURWOXQvdnhLUlBTczdjTngxOWR4LzByNUd4Yz2pdGltZXN0YW1wsjE1MjA0NDU5OTMuOTYyMDUwNw=='), 'notACorrectHash', marks=pytest.mark.xfail(strict=True)),
    pytest.param(base64.b64encode(b'\x82\xa9signature\xda\x02\xacGNk49I43+Vnfnh6y67PozBfvznq2jlW5uI14EAVKvY15NwCMmZj9N05jdIfG5sAXrrc8s/oQ+xu+FIa87vO5CF7vWznH3hy45u7yyEbIQA89te1cCJ5MSn/v+a0pDKSQcGWZ7ksd9KjtIqYdzvXNjCFdlZKM4F8lMKD4dUHpFmUjdYRs/vYsXBGrRZKT9zGp0AfJjLxcb2QKQvND2Y31hgzep0gtN9ROOyKiERyGQCScSeEzsSbgTjuO0ZcLQbBqcHjDvypM4u5h5TQnyDjYrqnzsvItMzS18QrtTH9YOWCNBKYCzgCDaPZr+0O+KOwCvSx3OEepLcbmovo2W9Z4QBFNvWwVxf5FS9gulSeKASgEQ37APqkUZ+WB2pjLr32yZ6duUo8EsWprBkSu3usSBkyRxN4JgV/O2x+JgARPTZR86dQWIeWSMw/fpdvqGzcgJy3M8wjVfzRGKM/P5a+Rcgg+1+p05hrthIT6ejQgMD9vd62ZAEHkdoqhjzY6rnsJeKKV9noSECTAWh8oJPCLz+issx2niE+4HUVIAr8t510roJYkHZqu7YWFXjGLj+SYUelbd6qTxuHtQK0u39bTJUdQtQm20QCgtFkx2Vu6kZmCUY/n07x3Ef4hb5CWLmeTpBh0Bqp/YUf6DBDlwRLyFMtuiu9xcK0zjnFFVDSNuiI=\xa9timestamp\xda\x03\xccgqlzaWduYXR1cmXaAqxKOC9OMHRsWEFtWklCcmZSWnhTZmtqWGRJcjBnTTZFdXlaVThPZUI4c0I2ODlRZ2lrS1gxZzdtcFNHTXFKUmdhZk81cS9mZmhGbExBd1prTWx3MjVZQUMrNCtOM2VZM0ZIOGgvekRnU1NPZHBnWUdZL3NDYlBwS0R1TGVrTVI0YTNNK3hxZUgva0JoZUdNTTEzcEl0OURWT2FpaUpLdUVlTFI5Slk0ZG8vSmw2Y1VOVXZWVzlDMHF1cjRwUGJpZThiQ3BnMmJpU1phMy9YMk4wUjkrR09TcTFLT3kzUkY0ckhaZEVKRE13OUpDQmRnRDJHZlZET2wySytqa2VKQUhhZmErTzV3NjRTb011d0R3ZVYzTGxZZ1JON1pOeHJURTZxN3dMUEtGWWJTWEU3bGlmTC8zeUE1dDFSV3VGRFpCaUxKQjArbEVhNWFsZkt1bnlPYmNPODI3dXBMYWlwRmN1WHA3U1ZnN013OU93K3g0U0p3L01hUU42bFM0c1pjU1lGaW5icURxQWlFWVhLRFV6bWlidzRFZTM5T1hvNzR0ak13ZisrY04rQU4zRlBuaTJYUUpTbCtxbDUwQWhVc0paTGZXMHcxSm1wUWJJMUNOaHJyNDJmZGVjUC9Kejdhd2MzMmhFOTZHVlRveTBod3IzcG52S2NvUVl0VEdHOWNqeFZxUzZQb2RZMHF0eUJkOTdZVTg5bmdmR0d5aVNuTmFhcDh3MG5GdEtLOXMwR1hQRkZLZHo5TTFXREZWaGl5aFpMNXQvamZROG5sblNsck1wYml0cWdHeERYSENNK0dIZk4zbExhNXJUa3FWa0NCTTVpTmpUUlppZnBvR09xakYzT214bFg5UmlnVUQzdmtZUURWOXQvdnhLUlBTczdjTngxOWR4LzByNUd4Yz2pdGltZXN0YW1wsjE1MjA0NDU5OTMuOTYyMDUwNw=='), 'notACorrectHashEither', marks=pytest.mark.xfail(strict=True)),
]


REGISTRATION_MESSAGES = [
    base64.b64encode(
        umsgpack.packb({
            'bodyType': 1,
            'messageBody': base64.b64encode(umsgpack.packb({
                'publicKey': "boguspubkey"
            }))
        })
    ),
    pytest.param(
        base64.b64encode(
            umsgpack.packb({
                "data": "this message is malformed"
            })
        ),
        marks=pytest.mark.xfail(strict=True),
        id='registration_malformedMessage'
    ),
]

ACCESS_CONTROL_LISTS = [
    [{'reader': 'validAddress', 'key': 'someKey'},],
    pytest.param(None, marks=pytest.mark.xfail(strict=True), id='ACL_noACL'),
    pytest.param([{'reader': 'invalidAddress', 'key': 'someKey'},], marks=pytest.mark.xfail(strict=True), id='ACL_nonExistentAddress'),
]


PUBLIC_MESSAGE_ENVELOPES = [
    {
        'message': base64.b64encode(msgpack.packb({
            'messageBody': {
                'bodyType': 1
            },
            'dossierSalt': base64.b64encode(b'\xbd\x02\xbf;\xb5\x16\x97\xdft\x84\xb3\xa6\xba\xf1\xb1\x9b\xbbl\x8e\xde\xd6s\xb5\xd0\x16\xdbJ\\\xa4\xd3\xa2\x15\xd5\x0c\x9d\x9c\xd8\xfd"=')
        })),
        'dossierHash': b'n5jrh3gy+A6HP7+bhartYPLZ0PKuiZI0uVcdfZcrOqs=',
        'bodyHash': '3XbGm+lGWHfvp/R/RPDP8SO+xw3AYx34U+kBk2f1m2Q=',
    },
    pytest.param({
        'message': base64.b64encode(msgpack.packb({
            'messageBody': msgpack.packb({
                'bodyType': 1
            }),
            'dossierSalt': base64.b64encode(b'\xbd\x02\xbf;\xb5\x16\x97\xdft\x84\xb3\xa6\xba\xf1\xb1\x9b\xbbl\x8e\xde\xd6s\xb5\xd0\x16\xdbJ\\\xa4\xd3\xa2\x15\xd5\x0c\x9d\x9c\xd8\xfd"=')
        })),
        'dossierHash': 'INCORRECTDOSSIERHASH==',
        'bodyHash': '3XbGm+lGWHfvp/R/RPDP8SO+INCORRECTHASH+kBk2f1m2Q=',
    }, marks=pytest.mark.xfail(strict=True), id='publicMessage_hashMismatch')
]

INVITE_MESSAGE_BODIES = [
    {
        'bootstrapNode': 'localhost:5000',
        'bootstrapAddr': 'idk what this is',
        'offeringAddr': 'address of the sender ( a bank )',
        'serviceAnnouncementMessage': 'idk what this is for',
        'serviceOfferingID': 'ID for field above',
        'inviteName': 'name of the invite'
    },
    pytest.param({
        b'a': 'b'
    }, marks=pytest.mark.xfail(strict=True), id='invite_malformedMessage'),
    pytest.param({
        b'bootstrapNode': 'localhost:5000',
    }, marks=pytest.mark.xfail(strict=True), id='invite_missingBootstrapAddr'),
    pytest.param({
        b'bootstrapNode': 'localhost:5000',
        b'bootstrapAddr': 'idk what this is',
    }, marks=pytest.mark.xfail(strict=True), id='invite_missingOfferingAddr'),
    pytest.param({
        b'bootstrapNode': 'localhost:5000',
        b'bootstrapAddr': 'idk what this is',
        b'offeringAddr': 'address of the sender ( a bank )',
    }, marks=pytest.mark.xfail(strict=True), id='invite_missingServiceAnnouncementMessage'),
    pytest.param({
        b'bootstrapNode': 'localhost:5000',
        b'bootstrapAddr': 'idk what this is',
        b'offeringAddr': 'address of the sender ( a bank )',
        b'serviceAnnouncementMessage': 'idk what this is for',
    }, marks=pytest.mark.xfail(strict=True), id='invite_missingServiceOfferingID'),
    pytest.param({
        b'bootstrapNode': 'localhost:5000',
        b'bootstrapAddr': 'idk what this is',
        b'offeringAddr': 'address of the sender ( a bank )',
        b'serviceAnnouncementMessage': 'idk what this is for',
        b'serviceOfferingID': 'ID for field above',
    }, marks=pytest.mark.xfail(strict=True), id='invite_missingInviteName'),
]


INVITE_AES_KEY = b'asdfzxcv'


INVITE_MESSAGE_EXAMPLE = {
    'message': base64.b64encode(umsgpack.packb({
        'messageBody': base64.b64encode(umsgpack.packb({
            'inviteName': AES(INVITE_AES_KEY, b'0123').encrypt(b"invite name")
        }))
    }))
}


REGISTRATION_MESSAGE_BODIES = [
    {
        'inviteMsgID': 'messageID',
        'publicNickname': 'fulano',
        'keyProof': RSA(identity.TELEFERIC_PUBLIC_KEY).encrypt(
            umsgpack.packb({
                'key': 'asdfzxcv',
                'nonce': '0123'
            })
        ),
        'inviteName': RSA(identity.TELEFERIC_PUBLIC_KEY).encrypt(b"invite name"),
        'publicKey': b"""-----BEGIN PUBLIC KEY-----
        MCQwDQYJKoZIhvcNAQEBBQADEwAwEAIJALn94I4UDcVNAgMBAAE=
        -----END PUBLIC KEY-----
        """, # 64 bits rsa just for testing
    }
]



