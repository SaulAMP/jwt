package login.aprendiendologin.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegistrerRequest {
    String username;
    String password;
    String firstname;
    String lastname;
    String country;
}
