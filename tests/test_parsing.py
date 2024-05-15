import pytest

from typing import List

from pyrattle.pyrattle import PyDefender, ScanResult

def test_simple_scan_parsing():
    output : str = '''
Scan starting....
Scan finished
Scanning C:\\Users\\Administrator\\Downloads\\eciar.txt

\u003c===========================LIST OF DETECTED THREATS===========================\u003c
Threat                  : Virus:DOS/EICAR_Test_File
Resources              : 1 total
    file                : C:\\Users\\Administrator\\Downloads\\eciar.txt
'''
    pydef = PyDefender()
    result : ScanResult = pydef._parse_scan(output)

    assert result == ScanResult(is_threat=True, threat="Virus:DOS/EICAR_Test_File", ressources=1, file="C:\\Users\\Administrator\\Downloads\\eciar.txt")

def test_simple_signatures_parsing():
    output : str = '''
SignatureSet ID: 2af7fedeac57ab97dfa1e93a1242804430f8ddd1
SignatureSet ID: 54db641daf4c4594f41488f825aabceb1e59c740
SignatureSet ID: 562e7134a36acec6b1588772a21e1ca2661fad26
SignatureSet ID: 7e55e9e8a9673f33830ed9319ed7361290d266a2
SignatureSet ID: 800f72d913ce93582458994dd9dc4b5471c46383
SignatureSet ID: 97832ddc754883e61ab65a9f00b3d521dfb4c582
SignatureSet ID: d079a381f3c8e58e2b2016254c37ec244c26f1f4
SignatureSet ID: da089bff9feca996a367942645965ea908391d9a
SignatureSet ID: e9749d3d7617a0b6c674e268a421c6ec6c4f8a47
SignatureSet ID: f66888461d409a7ba1cc980fddb58e9545b6db4a
'''

    signatures : List[str] = [ "2af7fedeac57ab97dfa1e93a1242804430f8ddd1",
                              "54db641daf4c4594f41488f825aabceb1e59c740",
                              "562e7134a36acec6b1588772a21e1ca2661fad26",
                              "7e55e9e8a9673f33830ed9319ed7361290d266a2",
                              "800f72d913ce93582458994dd9dc4b5471c46383",
                              "97832ddc754883e61ab65a9f00b3d521dfb4c582",
                              "d079a381f3c8e58e2b2016254c37ec244c26f1f4",
                              "da089bff9feca996a367942645965ea908391d9a",
                              "e9749d3d7617a0b6c674e268a421c6ec6c4f8a47",
                              "f66888461d409a7ba1cc980fddb58e9545b6db4a"
    ]

    pydef = PyDefender()
    
    assert signatures == pydef._parse_signatures(output)