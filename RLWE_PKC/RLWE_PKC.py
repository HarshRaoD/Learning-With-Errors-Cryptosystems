import secrets
import numpy as np

# Check for correct numpy version
np_version = np.version.version
if np_version[:-2] != '1.24':
    print(f"WARNING: NumPy version! Please use NumPy version 1.24.x for the best experience. Use of an incorrect numpy version may cause the printing of polynomials to work differently. As the expected order of polynomial coefficients was changed in prior versions. In this implementation we expect the order to be highest to lowest degree.")

def poly_to_str(p) -> str:
    """Converts polynomial to string.  
    Assumes all coefficients are postive integers"""
    # Reverse the order an convert to int
    p2 = [int(el) for el in p[::-1]]
    p_stack = [""] * len(p2)
    
    # Handle constant term and x term
    p_stack[0] = str(p2[0]) if p2[0] != 0 else ""
    p_stack[1] = f"{p2[1]}x" if (p2[1] > 1) else ("x" if p2[1] == 1 else "")

    # Handle x^n terms
    for i in range(2, len(p2)):
        if p2[i] > 1:
            p_stack[i] = f"{p2[i]}x^{i}"
        elif p2[i] == 1:
            p_stack[i] = f"x^{i}"

    final_str = ""
    # Reverse back
    p_stack = p_stack[::-1]
    # Get final output
    first_thing = True
    for i in range(len(p_stack)):
        if len(p_stack[i]) > 0:
            final_str += (" + " if not first_thing else "") + p_stack[i]
            first_thing = False
        
    return final_str

class RLWE_Encrypt():
    """Performs encryption using RLWE Public Key Encryption Scheme"""
    def __init__(self, A_list, T_list, phi_x, q, max_error):
        self.A_list = np.array(A_list)
        self.T_list = np.array(T_list)
        self.phi_x = np.array(phi_x)
        self.q = q
        self.max_error = max_error
        self.n = len(A_list[0])
    
    def encrypt_message(self, message: list, max_additional_error = None):
        """ Parameters: 
        message: list of bits and be of the exact length needed.
        max_additional_error: the amount of additional error that will be introduced during public key encryption (if None program will calculate the max value)"""
        if len(message) > self.n:
            raise Exception(f"Message is too long for this scheme. Message Length must be {self.n}")
        elif len(message) < self.n:
            raise Exception(f"Message is too short for this scheme. Message Length must be {self.n}")

        # Find max_additional_error
        max_additional_error = ((self.q // 4) - self.max_error - 1) if max_additional_error is None else max_additional_error
        max_equation_weights = max_additional_error // self.max_error
        max_extra_errors = max_additional_error % self.max_error

        # Calculate equation & extra error freedom
        A_indexes = [secrets.randbelow(len(self.A_list)) for _ in range(max_equation_weights)]
        
        # Do weighted addition of equations
        A_new = np.polyadd(self.A_list[A_indexes[0]], self.A_list[A_indexes[1]]) % self.q
        T_new = np.polyadd(self.T_list[A_indexes[0]], self.T_list[A_indexes[1]]) % self.q
        for i in range(2, len(A_indexes)):
            A_new = np.polyadd(A_new, self.A_list[A_indexes[i]]) % self.q
            T_new = np.polyadd(T_new, self.T_list[A_indexes[i]]) % self.q

        # Add extra errors
        if max_extra_errors > 0:
            E_extra = np.array([secrets.randbelow(max_extra_errors) for _ in range(self.n)]) % self.q
            T_new = np.polyadd(T_new, E_extra) % self.q
            T_new = np.polydiv(T_new, self.phi_x)[1] % self.q

        # Add message
        new_message = [(self.q // 2) * m for m in message]
        T_send = np.polyadd(T_new, new_message) % self.q

        return A_new, T_send

class RLWE_Decrypt():
    """Performs the setup and decryption of RLWE Public Key Encryption Scheme"""
    def __init__(self, message_length: int, q=13, max_error=1, list_size=5, phi_x=None, secret=None) -> None:
        """
        Parameters:
        message_length: Length of message to be sent
        max_error: The maximum magnitude of error to be introduced while creating the public keys
        list_size: The number of valid A and T pairs to send as public key
        q: Base divisor for number space (All numbers will be mod q)
        phi_x: Base polynomial for the Space (If None will become x^n + 1)
        secret: Secret Key to be used (If None will be randomly generated)
        """
        if max_error > (q//8):
            raise Exception(f"max_error ({max_error}) cannot exceed q//8 ({q//8})")
        self.n = message_length
        self.q = q
        self.max_error = max_error
        # Assign phi_x
        if phi_x is None:
            self.phi_x = [1] + ([0] * (self.n - 1)) + [1]  # x^n + 1
        else:
            self.phi_x = phi_x
        # Handle Secret
        if secret is None:
            self.secret = [secrets.randbelow(self.q) for _ in range(self.n)]
        else:
            self.secret = secret

        # Generate A_list
        A_list = []
        for i in range(list_size):
            A = [secrets.randbelow(self.q) for _ in range(self.n)]
            A_list.append(A)
        self.A_list = np.array(A_list)
        self.T_list = None  # Will be calculated at time of sending public key (and stored)
    
    def _calculate_T(self, A, E):
        # Multiply A & S
        prod1 = np.polymul(A, self.secret)
        # Take mod q of each number
        prod2 = prod1 % self.q
        # Reduce the polynomial back to required degree (Or to fit in GF(2))
        prod3 = np.polydiv(prod2, self.phi_x)[1] % self.q  # [1] to take the remainder
        # Add the errors
        final_t = np.polyadd(prod3, E) % self.q  

        return final_t

    def get_public_keys(self):
        if self.T_list is None:
            # Calculate T_list
            T_list = []
            for i in range(len(self.A_list)):
                # Generate Es
                E_mags = [secrets.randbelow(self.max_error + 1) for _ in range(self.n)]
                E_signs = [(secrets.randbelow(2) * 2) - 1 for _ in range(self.n)]  # Generates +1 and -1
                E_final = [(E_mags[i] * E_signs[i]) % self.q for i in range(self.n)]  # Multiplies the sign to the errors

                T = self._calculate_T(self.A_list[i], E_final)
                T_list.append(T)
            # Store the T_list for future use
            self.T_list = np.array(T_list)
        
        return self.A_list, self.T_list, self.phi_x, self.q, self.max_error
    
    def decrypt_message(self, A_new, T_sent):
        # Find T_ideal
        T_ideal = self._calculate_T(A_new, [0]*len(A_new))  # No errors introduced this time
        
        # T_sent - T_ideal
        Message_Draft = T_sent - T_ideal

        # Get final Message
        final_message = []
        for m_bit in Message_Draft:
            message_bit = ((m_bit + (self.q//4)) % self.q) // (self.q//2)
            final_message.append(int(message_bit))

        return final_message
    

if __name__ == "__main__":
    rlwe_d = RLWE_Decrypt(4, q=105, max_error=4)
    MESSAGE = [0, 0, 1, 1]
    print(f"message = {MESSAGE}")
    # Get public keys
    A_list, T_list, phi_x, q, max_error = rlwe_d.get_public_keys()
    # Encrypt Message
    rlwe_e = RLWE_Encrypt(A_list, T_list, phi_x, q, max_error)
    A_new, T_send = rlwe_e.encrypt_message(MESSAGE)
    print(f"A_new = {poly_to_str(A_new)}\nT_send = {poly_to_str(T_send)}")
    # Decrypt Message
    decrypted_message = rlwe_d.decrypt_message(A_new, T_send)
    print(f"decrypted_message = {decrypted_message}")

