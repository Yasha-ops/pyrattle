from pyrattle import PyDefender

pydef = PyDefender()

signatures = pydef.listAllDynamicSignatures()

print(signatures)