package iam.casclient.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class MyController {

    @GetMapping("/")
    public String home() {
        return "redirect:/secured";
    }

    @GetMapping("/secured")
    public String securedPage(Model model, Principal principal) {
        // principal is available because the user is authenticated
        model.addAttribute("username", principal.getName());
        return "secured"; // Renders secured.html
    }
}