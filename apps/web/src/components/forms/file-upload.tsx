'use client';

import * as React from 'react';
import { Upload, X, FileIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

interface FileUploadProps {
  accept?: string;
  maxSize?: number;
  maxFiles?: number;
  onUpload: (files: File[]) => void;
  disabled?: boolean;
  className?: string;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function FileUpload({
  accept,
  maxSize = 10 * 1024 * 1024,
  maxFiles = 1,
  onUpload,
  disabled,
  className,
}: FileUploadProps) {
  const inputRef = React.useRef<HTMLInputElement>(null);
  const [files, setFiles] = React.useState<File[]>([]);
  const [errors, setErrors] = React.useState<string[]>([]);
  const [isDragOver, setIsDragOver] = React.useState(false);

  const acceptedTypes = React.useMemo(() => {
    if (!accept) return null;
    return accept.split(',').map((t) => t.trim().toLowerCase());
  }, [accept]);

  const validateFile = React.useCallback(
    (file: File): string | null => {
      if (file.size > maxSize) {
        return `${file.name} exceeds the maximum size of ${formatFileSize(maxSize)}`;
      }
      if (acceptedTypes) {
        const fileType = file.type.toLowerCase();
        const fileExt = `.${file.name.split('.').pop()?.toLowerCase()}`;
        const isAccepted = acceptedTypes.some(
          (type) =>
            type === fileType ||
            type === fileExt ||
            (type.endsWith('/*') && fileType.startsWith(type.replace('/*', '/')))
        );
        if (!isAccepted) {
          return `${file.name} is not an accepted file type`;
        }
      }
      return null;
    },
    [maxSize, acceptedTypes]
  );

  const handleFiles = React.useCallback(
    (fileList: FileList | null) => {
      if (!fileList) return;

      const newErrors: string[] = [];
      const validFiles: File[] = [];

      Array.from(fileList).forEach((file) => {
        const error = validateFile(file);
        if (error) {
          newErrors.push(error);
        } else {
          validFiles.push(file);
        }
      });

      const combined = [...files, ...validFiles].slice(0, maxFiles);
      if (files.length + validFiles.length > maxFiles) {
        newErrors.push(`Maximum of ${maxFiles} file${maxFiles !== 1 ? 's' : ''} allowed`);
      }

      setErrors(newErrors);
      setFiles(combined);
      onUpload(combined);
    },
    [files, maxFiles, validateFile, onUpload]
  );

  const removeFile = React.useCallback(
    (index: number) => {
      const updated = files.filter((_, i) => i !== index);
      setFiles(updated);
      setErrors([]);
      onUpload(updated);
    },
    [files, onUpload]
  );

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled) setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    if (!disabled) handleFiles(e.dataTransfer.files);
  };

  return (
    <div className={cn('space-y-2', className)}>
      <div
        className={cn(
          'flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-6 transition-colors',
          isDragOver && 'border-primary bg-primary/5',
          disabled
            ? 'cursor-not-allowed opacity-50'
            : 'cursor-pointer hover:border-primary/50'
        )}
        onClick={() => !disabled && inputRef.current?.click()}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        role="button"
        tabIndex={disabled ? -1 : 0}
        onKeyDown={(e) => {
          if (!disabled && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            inputRef.current?.click();
          }
        }}
      >
        <Upload className="mb-2 h-8 w-8 text-muted-foreground" />
        <p className="text-sm text-muted-foreground">
          Click to upload or drag and drop
        </p>
        {accept && (
          <p className="mt-1 text-xs text-muted-foreground">
            Accepted: {accept}
          </p>
        )}
        <p className="mt-1 text-xs text-muted-foreground">
          Max size: {formatFileSize(maxSize)}
        </p>
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          multiple={maxFiles > 1}
          className="hidden"
          onChange={(e) => {
            handleFiles(e.target.files);
            e.target.value = '';
          }}
          disabled={disabled}
        />
      </div>

      {errors.length > 0 && (
        <div className="space-y-1">
          {errors.map((error, index) => (
            <p key={index} className="text-xs text-destructive">
              {error}
            </p>
          ))}
        </div>
      )}

      {files.length > 0 && (
        <div className="space-y-1">
          {files.map((file, index) => (
            <div
              key={`${file.name}-${index}`}
              className="flex items-center gap-2 rounded-md border p-2 text-sm"
            >
              <FileIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
              <span className="flex-1 truncate">{file.name}</span>
              <span className="text-xs text-muted-foreground">
                {formatFileSize(file.size)}
              </span>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="h-6 w-6"
                onClick={(e) => {
                  e.stopPropagation();
                  removeFile(index);
                }}
              >
                <X className="h-3 w-3" />
                <span className="sr-only">Remove file</span>
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export { FileUpload };
export type { FileUploadProps };
