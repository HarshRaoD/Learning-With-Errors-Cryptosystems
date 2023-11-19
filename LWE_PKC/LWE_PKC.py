import numpy as np
import secrets

class LWE_Encrypt():
    """Performs encryption using LWE Public Key Encryption Scheme"""
    def __init__(self, A_list, T_list, q, max_error):
        self.A_list = np.array(A_list)
        self.T_list = np.array(T_list)
        self.q = q
        self.max_error = np.array(max_error)
        self.n = len(A_list[0])

    def encrypt_bit(self, message: int):
        """message must be a single bit."""
        # Find max_additional_error
        max_additional_error = (self.q // 4) - self.max_error - 1
        max_equation_weights = max_additional_error // self.max_error
        max_extra_errors = max_additional_error % self.max_error

        # Calculate equation & extra error freedom
        A_indexes = [secrets.randbelow(len(self.A_list)) for _ in range(max_equation_weights)]
        
        # TODO Increase Entropy here
        A_new = (self.A_list[A_indexes[0]] + self.A_list[A_indexes[1]]) % self.q
        T_new = (self.T_list[A_indexes[0]] + self.T_list[A_indexes[1]]) % self.q

        # Add Message
        new_message = message * (self.q // 2)
        T_send = (T_new + new_message) % self.q

        return A_new, T_send
    

class LWE_Decrypt():
    """Performs the setup and decryption of LWE Public Key Encryption Scheme"""
    def __init__(self, n: int, q=13, max_error=1, list_size=5, secret=None) -> None:
        """
        Parameters:
        n: Length of equations used to encrypt each bit
        max_error: The maximum magnitude of error to be introduced while creating the public keys
        list_size: The number of valid 
        q: Base divisor for number space (All numbers will be mod q)
        phi_x: Base polynomial for the Space (If None will become x^n + 1)
        secret: Secret Key to be used (If None will be randomly generated)
        """
        if max_error > (q//8):
            raise Exception(f"max_error ({max_error}) cannot exceed q//8 ({q//8})")
        self.n = n
        self.q = q
        self.max_error = max_error
        # Handle Secret
        if secret is None:
            self.secret = [secrets.randbelow(self.q) for _ in range(self.n)]
        else:
            self.secret = secret

        # Generate A_list
        A_list = []
        for _ in range(list_size):
            A = [secrets.randbelow(self.q) for _ in range(self.n)]
            A_list.append(A)
        self.A_list = np.array(A_list)
        self.T_list = None  # Will be calculated at time of sending public key (and stored)
    
    def get_public_keys(self):
        if self.T_list is None:
            # Calculate T_list
            # Generate Es
            E_mags = [secrets.randbelow(self.max_error + 1) for _ in range(len(self.A_list))]
            E_signs = [(secrets.randbelow(2) * 2) - 1 for _ in range(len(self.A_list))]  # Generates +1 and -1
            E_final = np.array([(E_mags[i] * E_signs[i]) % self.q for i in range(len(self.A_list))])  # Multiplies the sign to the errors

            T_no_errors = np.matmul(self.A_list, self.secret) % self.q
            T_with_errors = (T_no_errors + E_final) % self.q
            
            # Store the T_list for future use
            self.T_list = T_with_errors
        
        return self.A_list, self.T_list, self.q, self.max_error
    
    def decrypt_bit(self, A_new, T_sent):
        # Find T_ideal
        T_ideal = np.matmul(A_new, self.secret) % self.q
        
        # T_sent - T_ideal
        Message_Draft = T_sent - T_ideal

        # Get final Message
        final_message = ((Message_Draft + (self.q//4)) % self.q) // (self.q//2)

        return final_message


if __name__ == "__main__":
    rlwe_d = LWE_Decrypt(5, q=17, max_error=1)
    MESSAGE = 1
    print(f"message = {MESSAGE}")
    # Get public keys
    A_list, T_list, q, max_error = rlwe_d.get_public_keys()
    # Encrypt Message
    rlwe_e = LWE_Encrypt(A_list, T_list, q, max_error)
    A_new, T_send = rlwe_e.encrypt_bit(MESSAGE)
    print(f"A_new = {A_new}\nT_send = {T_send}")
    # Decrypt Message
    decrypted_message = rlwe_d.decrypt_bit(A_new, T_send)
    print(f"decrypted_message = {decrypted_message}")