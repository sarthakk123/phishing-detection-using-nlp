
import { useToast } from "@/hooks/use-toast"
import {
  Toast,
  ToastClose,
  ToastDescription,
  ToastProvider,
  ToastTitle,
  ToastViewport,
} from "@/components/ui/toast"
import { ShieldAlert } from "lucide-react"

export function Toaster() {
  const { toasts } = useToast()

  return (
    <ToastProvider>
      {toasts.map(function ({ id, title, description, action, variant, ...props }) {
        const isHighThreat = title?.includes("High Threat");
        
        return (
          <Toast key={id} {...props} variant={variant} className={isHighThreat ? "animate-pulse border-phishing" : ""}>
            <div className="grid gap-1">
              {title && (
                <ToastTitle className="flex items-center">
                  {isHighThreat && <ShieldAlert className="h-4 w-4 mr-2 text-phishing" />}
                  {title}
                </ToastTitle>
              )}
              {description && (
                <ToastDescription>{description}</ToastDescription>
              )}
            </div>
            {action}
            <ToastClose />
          </Toast>
        )
      })}
      <ToastViewport />
    </ToastProvider>
  )
}
