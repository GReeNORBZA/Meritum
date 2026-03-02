'use client';

import * as React from 'react';
import {
  useForm,
  FormProvider,
  Controller,
  useFormContext,
  type UseFormReturn,
  type FieldValues,
  type FieldPath,
  type ControllerProps,
  type DefaultValues,
  type SubmitHandler,
} from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { type z } from 'zod';
import { Label } from '@/components/ui/label';
import { Button, type ButtonProps } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { Loader2 } from 'lucide-react';

// ---------- FormWrapper ----------

interface FormWrapperProps<T extends FieldValues> {
  schema: z.ZodType<T>;
  defaultValues: DefaultValues<T>;
  onSubmit: SubmitHandler<T>;
  children: React.ReactNode | ((form: UseFormReturn<T>) => React.ReactNode);
  className?: string;
}

function FormWrapper<T extends FieldValues>({
  schema,
  defaultValues,
  onSubmit,
  children,
  className,
}: FormWrapperProps<T>) {
  const form = useForm<T>({
    resolver: zodResolver(schema),
    defaultValues,
  });

  return (
    <FormProvider {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className={cn('space-y-6', className)}
        noValidate
      >
        {typeof children === 'function' ? children(form) : children}
      </form>
    </FormProvider>
  );
}

// ---------- FormField ----------

interface FormFieldProps<T extends FieldValues> {
  name: FieldPath<T>;
  label?: string;
  description?: string;
  required?: boolean;
  className?: string;
  children: ControllerProps<T>['render'];
}

function FormField<T extends FieldValues>({
  name,
  label,
  description,
  required,
  className,
  children,
}: FormFieldProps<T>) {
  const { control, formState: { errors } } = useFormContext<T>();
  const error = errors[name];

  return (
    <div className={cn('space-y-2', className)}>
      {label && (
        <Label
          htmlFor={name}
          className={cn(
            error && 'text-destructive',
            required && "after:content-['*'] after:ml-0.5 after:text-destructive"
          )}
        >
          {label}
        </Label>
      )}
      <Controller name={name} control={control} render={children} />
      {description && !error && (
        <p className="text-xs text-muted-foreground">{description}</p>
      )}
      {error && (
        <p className="text-xs text-destructive">{error.message as string}</p>
      )}
    </div>
  );
}

// ---------- FormSubmit ----------

interface FormSubmitProps extends ButtonProps {
  isLoading?: boolean;
  loadingText?: string;
}

function FormSubmit({
  children = 'Submit',
  isLoading = false,
  loadingText = 'Submitting...',
  disabled,
  className,
  ...props
}: FormSubmitProps) {
  return (
    <Button
      type="submit"
      disabled={isLoading || disabled}
      className={className}
      {...props}
    >
      {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
      {isLoading ? loadingText : children}
    </Button>
  );
}

export { FormWrapper, FormField, FormSubmit };
export type { FormWrapperProps, FormFieldProps, FormSubmitProps };
