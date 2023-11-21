import secrets
import numpy as np

class LWE_Encrypt():
    """Performs encryption using LWE Public Key Encryption Scheme"""
    def __init__(self, A_list, T_list, q, max_error):
        self.A_list = np.array(A_list)
        self.T_list = np.array(T_list)
        self.q = q
        self.max_error = max_error
        self.n = len(A_list[0])

    def encrypt_bit(self, message: int):
        """message must be a single bit."""
        # Find max_additional_error
        max_additional_error = (self.q // 4) - self.max_error - 1
        # max_equation_weights = max_additional_error // self.max_error

        # Weak Parameter 1
        max_equation_weights = 2
        max_extra_errors = max_additional_error % self.max_error

        if max_equation_weights <= 1:
            raise Exception("Entropy of public Key is too small. Please increase the size of q")
        # print(f"max_additional_error = {max_additional_error}\nmax_equation_weights = {max_equation_weights}\nmax_extra_errors = {max_extra_errors}")

        # Calculate equation & extra error freedom
        A_indexes = [secrets.randbelow(len(self.A_list)) for _ in range(max_equation_weights)]
        
        # Do weighted addition of equations
        A_new = (self.A_list[A_indexes[0]] + self.A_list[A_indexes[1]]) % self.q
        T_new = (self.T_list[A_indexes[0]] + self.T_list[A_indexes[1]]) % self.q
        for i in range(2, len(A_indexes)):
            A_new = (A_new + self.A_list[A_indexes[i]]) % self.q
            T_new = (T_new + self.T_list[A_indexes[i]]) % self.q
        
        # Add extra errors
        if max_extra_errors > 1:
            E_extra_mags = secrets.randbelow(max_extra_errors)
            E_extra_signs = (secrets.randbelow(2) * 2) - 1   # Generates +1 and -1
            E_extra = (E_extra_mags * E_extra_signs) % self.q  # Multiplies the sign to the errors
            T_new = (T_new + E_extra) % self.q

        # Add Message
        new_message = message * (self.q // 2)
        T_send = (T_new + new_message) % self.q

        return A_new, T_send
    
    def encrypt_message(self, message: list):
        """message must be a list of single bits."""
        A_new_list = []
        T_send_list = []
        
        for bit in message:
            A_new, T_send = self.encrypt_bit(bit)
            A_new_list.append(A_new)
            T_send_list.append(T_send)
        
        return A_new_list, T_send_list
    

class LWE_Decrypt():
    """Performs the setup and decryption of LWE Public Key Encryption Scheme"""
    def __init__(self, n: int, q=13, max_error=1, list_size=5, secret=None) -> None:
        """
        Parameters:
        n: Length of equations used to encrypt each bit (Also length of secret)
        max_error: The maximum magnitude of error to be introduced while creating the public keys
        list_size: The number of valid A & T pairs to send as public key
        q: Base divisor for number space (All numbers will be mod q)
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
            self.T_list = np.array(T_with_errors)
        
        return self.A_list, self.T_list, self.q, self.max_error
    
    def decrypt_bit(self, A_new, T_sent):
        # Find T_ideal
        T_ideal = np.matmul(A_new, self.secret) % self.q
        
        # T_sent - T_ideal
        Message_Draft = T_sent - T_ideal

        # Get final Message
        final_message = ((Message_Draft + (self.q//4)) % self.q) // (self.q//2)

        return final_message
    
    def decrypt_message(self, A_new_list, T_sent_list):
        final_message = []
        for i in range(len(T_sent_list)):
            final_message.append(self.decrypt_bit(A_new_list[i], T_sent_list[i]))
        
        return final_message


if __name__ == "__main__":
    lwe_d = LWE_Decrypt(n=5, q=109, max_error=4, list_size=12)
    MESSAGE = [1, 1, 0]
    print(f"message = {MESSAGE}")
    # Get public keys
    A_list, T_list, q, max_error = lwe_d.get_public_keys()
    # Encrypt Message
    lwe_e = LWE_Encrypt(A_list, T_list, q, max_error)
    A_new, T_send = lwe_e.encrypt_message(MESSAGE)
    print(f"A_new = {A_new}\nT_send = {T_send}")
    # Decrypt Message
    decrypted_message = lwe_d.decrypt_message(A_new, T_send)
    print(f"decrypted_message = {decrypted_message}")