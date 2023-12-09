# Learning with Errors based cryptosystems
This project was created as a part of the Applied Cryptography (CZ4010) course at Nanyang Technological University, Singapore. Through this project we have aimed to cover the following:  
1. The Learning With Errors Problem (LWE) and its use in Public Key Cryptography (PKC)
2. The Ring Learning With Errors Problem (RLWE) and its use in Public Key Cryptography (PKC)
3. Appropriate Parameters for LWE & RLWE cryptosystems
4. The Arora Ge Algebric Attack
5. Additional Applications of LWE/RLWE PKCs

This repo contains:
```
.
├── Learning_with_Errors.pdf           # Final Presentation
├── LWE_PKC                 
│   ├── LWE_PKC.py                     # Module with PKC Implementation using LWE
│   ├── Slide_Example_LWE.ipynb        # Step by Step implementation of LWE
│   └── LWE_Arora_Ge_Attack.ipynb      # Step by Step implementation of Arora Ge Algebric Attack
├── RLWE_PKC
│   ├── RLWE_PKC.py                    # Module with PKC Implementation using RLWE
│   └── Slide_Example.ipynb            # Step by Step implementation of RLWE
├── utils.py                           # Extra Modules to convert regular text into bitstreams
├── requirements.txt                   # Prerequisite packages used
├── environment.yml
├── .gitignore
└── README.md
```

## Presentation Link
The presentation can be viewed:   
1. PDF -> [(here)](https://github.com/HarshRaoD/Applied-Cryptography-Project/blob/main/Learning_With_Errors.pdf) 
2. PowerPoint Presentation -> [(here)](https://entuedu-my.sharepoint.com/:p:/g/personal/harshrao001_e_ntu_edu_sg/EXBONLFc4klHqWMUNiM3QMsB7JF96xFM6ahDaq0gO5UxDA?e=XQvLEF)

## Authors
1. Harsh Rao Dhanyamraju [(HarshRaoD)](https://github.com/HarshRaoD)
2. Rahul George [(RahulG1309)](https://github.com/RahulG1309)

## Setup
1. Create a new virtual environment
2. Enter the same virtual environment
3. ```pip install -r requirements.txt```
4. You can then run ```python RLWE_PKC/RLWE_PKC.py```
