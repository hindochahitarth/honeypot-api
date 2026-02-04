import com.guvi.honeypot.model.ApiResponse;
import com.guvi.honeypot.model.InputRequest;
import com.guvi.honeypot.service.HoneyPotService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class HoneyPotController {

    private final HoneyPotService honeyPotService;
    private static final String API_KEY = "SECRET123";

    public HoneyPotController(HoneyPotService honeyPotService) {
        this.honeyPotService = honeyPotService;
    }

    @PostMapping("/honeypot")
    public ResponseEntity<ApiResponse> handleHoneypot(
            @RequestHeader(value = "x-api-key", required = false) String apiKey,
            @RequestBody(required = false) InputRequest request) { // required=false to handle empty body gracefully
        
        // 1. Security Check
        if (!API_KEY.equals(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // 2. Validate Request Body
        if (request == null) {
            System.out.println("Error: Request body is null");
            return ResponseEntity.badRequest().build();
        }

        // Allow missing history/metadata (initialize if null in service or here)
        if (request.getSessionId() == null || request.getSessionId().isEmpty()) {
             System.out.println("Error: sessionId is missing");
             return ResponseEntity.badRequest().build();
        }
        
        if (request.getMessage() == null || request.getMessage().getText() == null) {
             System.out.println("Error: message or message text is missing");
             return ResponseEntity.badRequest().build();
        }

        // 3. Process Request
        ApiResponse response = honeyPotService.processRequest(request);
        return ResponseEntity.ok(response);
    }

}
