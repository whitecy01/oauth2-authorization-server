package com.oauth.auth_server.clientregistration.controller;


import com.oauth.auth_server.clientregistration.service.ClientService;
import com.oauth.auth_server.clientregistration.thymeleaf.ClientForm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequiredArgsConstructor
@RequestMapping("/admin/clients")
public class ClientAdminPageController {

    private final ClientService clientService;

    @GetMapping
    public String list(Model model) {
        var clients = clientService.list();
        model.addAttribute("clients", clients);
        model.addAttribute("activeClientCount", clients.stream().filter(client -> client.client().isActive()).count());
        if (!model.containsAttribute("form")) {
            model.addAttribute("form", new ClientForm());
        }
        return "clients/list";
    }

    @GetMapping("/new")
    public String newForm() {
        return "redirect:/admin/clients";
    }

    @PostMapping
    public String create(@ModelAttribute("form") ClientForm form) {
        clientService.create(form);
        return "redirect:/admin/clients";
    }

    @GetMapping("/{clientId}")
    public String detail(@PathVariable("clientId") String clientId, Model model) {
        model.addAttribute("detail", clientService.getDetail(clientId));
        return "clients/detail";
    }
}
